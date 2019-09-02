#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import json
import logging
import argparse
import signal
import multiprocessing

log = logging.getLogger()
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
from lib.cuckoo.common.colors import red
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database, Task, TASK_REPORTED, TASK_COMPLETED
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING
from lib.cuckoo.core.plugins import GetFeeds, RunProcessing, RunSignatures
from lib.cuckoo.core.plugins import RunReporting
from lib.cuckoo.core.startup import init_modules, init_yara, ConsoleHandler

repconf = Config("reporting")
if repconf.mongodb.enabled:
    from bson.objectid import ObjectId
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure

if repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
    from elasticsearch import Elasticsearch
    baseidx = repconf.elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(
         hosts=[{
             "host": repconf.elasticsearchdb.host,
             "port": repconf.elasticsearchdb.port,
         }],
         timeout=300
     )


def process(target=None, copy_path=None, task=None, report=False, auto=False, capeproc=False):
    # This is the results container. It's what will be used by all the
    # reporting modules to make it consumable by humans and machines.
    # It will contain all the results generated by every processing
    # module available. Its structure can be observed through the JSON
    # dump in the analysis' reports folder. (If jsondump is enabled.)
    results = { }
    results["statistics"] = { }
    results["statistics"]["processing"] = list()
    results["statistics"]["signatures"] = list()
    results["statistics"]["reporting"] = list()
    GetFeeds(results=results).run()
    RunProcessing(task=task.to_dict(), results=results).run()
    RunSignatures(task=task.to_dict(), results=results).run()
    task_id = task.to_dict()["id"]
    if report:
        if repconf.mongodb.enabled:
            host = repconf.mongodb.host
            port = repconf.mongodb.port
            db = repconf.mongodb.db
            conn = MongoClient(host,
                               port=port,
                               username=repconf.mongodb.get("username", None),
                               password=repconf.mongodb.get("password", None),
                               authSource=db)
            mdata = conn[db]
            analyses = mdata.analysis.find({"info.id": int(task_id)})
            if analyses.count() > 0:
                log.debug("Deleting analysis data for Task %s" % task_id)
                for analysis in analyses:
                    for process in analysis["behavior"].get("processes", []):
                        for call in process["calls"]:
                            mdata.calls.remove({"_id": ObjectId(call)})
                    mdata.analysis.remove({"_id": ObjectId(analysis["_id"])})
            conn.close()
            log.debug("Deleted previous MongoDB data for Task %s" % task_id)

        if repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
            analyses = es.search(
                           index=fullidx,
                           doc_type="analysis",
                           q="info.id: \"%s\"" % task_id
                       )["hits"]["hits"]
            if analyses:
                for analysis in analyses:
                    esidx = analysis["_index"]
                    esid = analysis["_id"]
                    # Check if behavior exists
                    if analysis["_source"]["behavior"]:
                        for process in analysis["_source"]["behavior"]["processes"]:
                            for call in process["calls"]:
                                es.delete(
                                    index=esidx,
                                    doc_type="calls",
                                    id=call,
                                )
                    # Delete the analysis results
                    es.delete(index=esidx, doc_type="analysis", id=esid)
        if auto or capeproc:
            reprocess = False
        else:
            reprocess = report

        RunReporting(task=task.to_dict(), results=results, reprocess=reprocess).run()
        Database().set_status(task_id, TASK_REPORTED)

        if auto:
            if cfg.cuckoo.delete_original and os.path.exists(target):
                os.unlink(target)

            if cfg.cuckoo.delete_bin_copy and os.path.exists(copy_path):
                os.unlink(copy_path)


def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def init_logging(auto=False, tid=0, debug=False):
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)
    if not os.path.exists(os.path.join(CUCKOO_ROOT, "log")):
        os.makedirs(os.path.join(CUCKOO_ROOT, "log"))
    if auto:
        cfg = Config()
        if cfg.logging.enabled:
            days = cfg.logging.backupCount
            interval = cfg.logging.interval
            fh = logging.handlers.TimedRotatingFileHandler(os.path.join(CUCKOO_ROOT, "log", "process.log"),
                                                           when=interval, backupCount=days)
        else:
            fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "process.log"))
    else:
        fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "process-%s.log" % tid))

    fh.setFormatter(formatter)
    log.addHandler(fh)

    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    logging.getLogger("urllib3").setLevel(logging.WARNING)


def autoprocess(parallel=1, failed_processing=False):
    maxcount = cfg.cuckoo.max_analysis_count
    count = 0
    db = Database()

    # Respawn a worker process every 1000 tasks just in case we
    # have any memory leaks.
    pool = multiprocessing.Pool(parallel, init_worker, maxtasksperchild=1000)
    pending_results = []

    try:
        # CAUTION - big ugly loop ahead.
        while count < maxcount or not maxcount:

            # Pending_results maintenance.
            for ar, tid, target, copy_path in list(pending_results):
                if ar.ready():
                    if ar.successful():
                        log.info("Task #%d: reports generation completed", tid)
                    else:
                        try:
                            ar.get()
                        except:
                            log.exception("Exception when processing task ID %u.", tid)
                            db.set_status(tid, TASK_FAILED_PROCESSING)

                    pending_results.remove((ar, tid, target, copy_path))

            # If still full, don't add more (necessary despite pool).
            if len(pending_results) >= parallel:
                time.sleep(5)
                continue

            # If we're here, getting parallel tasks should at least
            # have one we don't know.
            if failed_processing:
                tasks = db.list_tasks(status=TASK_FAILED_PROCESSING, limit=parallel,
                                  order_by=Task.completed_on.asc())
            else:
                tasks = db.list_tasks(status=TASK_COMPLETED, limit=parallel,
                                  order_by=Task.completed_on.asc())

            added = False
            # For loop to add only one, nice. (reason is that we shouldn't overshoot maxcount)
            for task in tasks:
                # Not-so-efficient lock.
                if task.id in [tid for ar, tid, target, copy_path
                               in pending_results]:
                    continue

                log.info("Processing analysis data for Task #%d", task.id)

                if task.category == "file":
                    sample = db.view_sample(task.sample_id)
                    copy_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", sample.sha256)
                else:
                    copy_path = None

                args = task.target, copy_path
                kwargs = dict(report=True, auto=True, task=task)
                result = pool.apply_async(process, args, kwargs)

                pending_results.append((result, task.id, task.target, copy_path))

                count += 1
                added = True
                break

            if not added:
                # don't hog cpu
                time.sleep(5)

    except KeyboardInterrupt:
        pool.terminate()
        raise
    except:
        import traceback
        traceback.print_exc()
    finally:
        pool.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("id", type=str,
                        help="ID of the analysis to process (auto for continuous processing of unprocessed tasks).")
    parser.add_argument("-c", "--caperesubmit", help="Allow CAPE resubmit processing.", action="store_true",
                        required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-r", "--report", help="Re-generate report", action="store_true", required=False)
    parser.add_argument("-s", "--signatures", help="Re-execute signatures on the report", action="store_true",
                        required=False)
    parser.add_argument("-p", "--parallel", help="Number of parallel threads to use (auto mode only).", type=int,
                        required=False, default=1)
    parser.add_argument("-fp", "--failed-processing", help="reprocess failed processing", action="store_true",
                        required=False, default=False)
    args = parser.parse_args()

    init_yara()
    init_modules()

    if args.id == "auto":
        init_logging(auto=True, debug=args.debug)
        autoprocess(parallel=args.parallel, failed_processing=args.failed_processing)
    else:
        if not os.path.exists(os.path.join(CUCKOO_ROOT, "storage", "analyses", args.id)):
            sys.exit(red("\n[-] Analysis folder doesn't exist anymore\n"))
        init_logging(tid=args.id, debug=args.debug)
        task = Database().view_task(int(args.id))
        if args.signatures:
            report = os.path.join(CUCKOO_ROOT, "storage", "analyses", args.id, "reports", "report.json")
            if not os.path.exists(report):
                sys.exit("File {} doest exist".format(report))

            results = json.load(open(report))
            if results is not None:
                RunSignatures(task=task.to_dict(), results=results).run()
        else:
            process(task=task, report=args.report, capeproc=args.caperesubmit)


if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
