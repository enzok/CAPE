#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import argparse
import zlib
import json
import re

log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.startup import ConsoleHandler


repconf = Config("reporting")
if repconf.mongodb.enabled:
    from bson.objectid import ObjectId
    from pymongo import MongoClient
    host = repconf.mongodb.host
    port = repconf.mongodb.port
    db = repconf.mongodb.db
    conn = MongoClient(host, port)
    mdata = conn[db]
else:
    print("Mongodb not configured, exiting...")
    sys.exit(1)

if repconf.elasticsearchdb.enabled and repconf.elasticsearchdb.searchonly:
    from elasticsearch import Elasticsearch, ElasticsearchException
    baseidx = repconf.elasticsearchdb.index
    es = Elasticsearch(hosts=[{"host": repconf.elasticsearchdb.host,
                               "port": repconf.elasticsearchdb.port, }],
                       timeout=300)
else:
    print("Elasticsearch not configured, exiting...")
    sys.exit(1)


def process(task):
    task_id = task.to_dict()["id"]

    analyses = mdata.analysis.find({"info.id": int(task_id)})
    log.debug("Found %d analyses for %s" % (analyses.count(), task_id))
    if analyses.count() > 0:
        log.debug("Retrieving analysis data for Task %s" % task_id)
        for results in analyses:
            report = {}
            idxdate = results["info"]["started"].split(" ")[0]
            index_name = '{}-{}'.format(baseidx, idxdate)
            report["task_id"] = results["info"]["id"]
            report["info"] = results.get("info")
            report["target"] = results.get("target")
            report["summary"] = results.get("behavior", {}).get("summary")
            if report["summary"]:
                try:
                    report["summary"] = json.loads(zlib.decompress(report["summary"]))
                except Exception as err:
                    log.debug("Error decompressing summary results: %s", err)
                    pass
            report["network"] = results.get("network")
            report["malfamily"] = results.get("malfamily", "")
            report["signatures"] = results.get("signatures")
            if results["static"] and "strings" in results["static"]:
                report["strings"] = results.get("static", "").get("strings")
            report["cape"] = results.get("cape", "")
            if report["cape"]:
                try:
                    report["cape"] = json.loads(zlib.decompress(report["cape"]))
                except Exception as err:
                    log.debug("Error decompressing CAPE results: %s", err)
                    pass

            log.debug(report)

            # Create index and set maximum fields limit to 5000
            settings = {}
            settings["settings"] = {"index": {"mapping": {"total_fields": {"limit": "5000"}}}}

            if es.indices.exists(index=index_name):
                es.indices.put_settings(index=index_name, body=settings)
            else:
                es.indices.create(index=index_name, body=settings)

            # Store the report
            try:
                es.index(index=index_name, doc_type="analysis", id=report["info"]["id"], body=report)
            except ElasticsearchException as cept:
                log.warning(cept)
                error_saved = True
                dropdead = 1
                while error_saved and dropdead < 20:
                    if "mapper_parsing_exception" in cept.args[1] or "illegal_argument_exception" in cept.args[1]:
                        reason = cept.args[2]['error']['reason']
                        keys = re.findall(r'\[([^]]*)\]', reason)[0].split(".")

                        if "yara" in keys and "date" in keys:
                            for rule in report['target']['file']['yara']:
                                if "date" in rule['meta']:
                                    del rule['meta']['date']
                        else:
                            delcmd = "del report"
                            for k in keys:
                                delcmd += "['{}']".format(k)

                            try:
                                exec(compile(delcmd, '', 'exec')) in locals()

                            except Exception as cept:
                                log.error(cept)
                                error_saved = False

                        try:
                            es.index(index=index_name, doc_type="analysis", id=report["info"]["id"], body=report)
                            error_saved = False
                        except ElasticsearchException as cept:
                            dropdead += 1
                            log.error(cept)

                    else:
                        log.error("Failed to save results to elasticsearch db.")
                        error_saved = False


def init_logging(debug=False):
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)
    
    fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "es-migrate-batch.log"))

    fh.setFormatter(formatter)
    log.addHandler(fh)

    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    logging.getLogger("urllib3").setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("id", type=int, help="Starting ID of the analysis to migrate")
    parser.add_argument("count", type=int, help="Number of IDs to migrate")
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    args = parser.parse_args()

    init_logging(debug=args.debug)
    count = args.count

    if count <= 0:
        print "Count must be greater than 0."
        sys.exit(1)

    tid = args.id
    i = 0

    while i < count:
        task = Database().view_task(tid)
        try:
            if task:
                process(task)
                conn.close()
            else:
                log.info("Task does not exist.")
        except Exception as err:
            log.exception("Did not migrate task: %s", err)

        i += 1
        tid += 1

if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
