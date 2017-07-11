# Copyright (C) 2010-2015 Jose Palanco (jose.palanco@drainware.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import re

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import File

try:
    from elasticsearch import Elasticsearch
    HAVE_ELASTICSEARCH = True
except ImportError as e:
    HAVE_ELASTICSEARCH = False

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)


class ElasticsearchDB(Report):
    """Stores report in Elastic Search."""
    order = 9997

    def connect(self):
        """Connects to Elasticsearch database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        self.es = Elasticsearch(
            hosts = [{
                'host': self.options.get("host", "127.0.0.1"),
                'port': self.options.get("port", 9200),
            }],
            timeout = 300
        )

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to Elasticsearch.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_ELASTICSEARCH:
            raise CuckooDependencyError("Unable to import elasticsearch "
                                        "(install with `pip install elasticsearch`)")

        self.connect()
        index_prefix  = self.options.get("index", "cuckoo")
        search_only   = self.options.get("searchonly", False)

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = dict(results)

        idxdate = report["info"]["started"].split(" ")[0]
        self.index_name = '{0}-{1}'.format(index_prefix, idxdate)

        if not search_only:
            if not "network" in report:
                report["network"] = {}

            # Store API calls in chunks for pagination in Django
            if "behavior" in report and "processes" in report["behavior"]:
                new_processes = []
                for process in report["behavior"]["processes"]:
                    new_process = dict(process)
                    chunk = []
                    chunks_ids = []
                    # Loop on each process call.
                    for index, call in enumerate(process["calls"]):
                        # If the chunk size is 100 or if the loop is completed then
                        # store the chunk in Elastcisearch.
                        if len(chunk) == 100:
                            to_insert = {"pid": process["process_id"],
                                         "calls": chunk}
                            pchunk = self.es.index(index=self.index_name,
                                                   doc_type="calls", body=to_insert)
                            chunk_id = pchunk['_id']
                            chunks_ids.append(chunk_id)
                            # Reset the chunk.
                            chunk = []

                        # Append call to the chunk.
                        chunk.append(call)

                    # Store leftovers.
                    if chunk:
                        to_insert = {"pid": process["process_id"], "calls": chunk}
                        pchunk = self.es.index(index=self.index_name, 
                                               doc_type="calls", body=to_insert)
                        chunk_id = pchunk['_id']
                        chunks_ids.append(chunk_id)

                    # Add list of chunks.
                    new_process["calls"] = chunks_ids
                    new_processes.append(new_process)

                # Store the results in the report.
                report["behavior"] = dict(report["behavior"])
                report["behavior"]["processes"] = new_processes

            # Add screenshot paths
            report["shots"] = []
            shots_path = os.path.join(self.analysis_path, "shots")
            if os.path.exists(shots_path):
                shots = [shot for shot in os.listdir(shots_path)
                         if shot.endswith(".jpg")]
                for shot_file in sorted(shots):
                    shot_path = os.path.join(self.analysis_path, "shots",
                                             shot_file)
                    screenshot = File(shot_path)
                    if screenshot.valid():
                        # Strip the extension as it's added later 
                        # in the Django view
                        report["shots"].append(shot_file.replace(".jpg", ""))

            if results.has_key("suricata") and results["suricata"]:
                if results["suricata"].has_key("tls") and len(results["suricata"]["tls"]) > 0:
                    report["suri_tls_cnt"] = len(results["suricata"]["tls"])
                if results["suricata"] and results["suricata"].has_key("alerts") and len(results["suricata"]["alerts"]) > 0:
                    report["suri_alert_cnt"] = len(results["suricata"]["alerts"])
                if results["suricata"].has_key("files") and len(results["suricata"]["files"]) > 0:
                    report["suri_file_cnt"] = len(results["suricata"]["files"])
                if results["suricata"].has_key("http") and len(results["suricata"]["http"]) > 0:
                    report["suri_http_cnt"] = len(results["suricata"]["http"])
        else:
            report = {}
            report["task_id"] = results["info"]["id"]
            report["info"]    = results.get("info")
            report["target"]  = results.get("target")
            report["summary"] = results.get("behavior", {}).get("summary")
            report["network"] = results.get("network")
            report["malfamily"] = results.get("malfamily", "")
            report["cape"] = results.get("cape", "")
            report["virustotal"] = results.get("virustotal")

        # Other info we want Quick access to from the web UI
        if results.has_key("virustotal") and results["virustotal"] and results["virustotal"].has_key("positives") and results["virustotal"].has_key("total"):
            report["virustotal_summary"] = "%s/%s" % (results["virustotal"]["positives"],results["virustotal"]["total"])

        # Create index and set maximum fields limit to 5000
        settings = {}
        settings["settings"] = {"index": {"mapping": {"total_fields": {"limit": "5000"}}}}
        if self.es.indices.exists(index=self.index_name):
            self.es.indices.put_settings(index=self.index_name, body=settings)
        else:
            self.es.indices.create(index=self.index_name, body=settings)

        # Store the report and retrieve its object id.
        try:
            self.es.index(index=self.index_name, doc_type="analysis", id=results["info"]["id"], body=report)
        except Exception as cept:
            error_saved = True
            while error_saved:
                desc = cept.message.split(",")[-1]
                if "date" in desc:
                    keys = re.findall(r'\[([^]]*)\]', desc)[0].split(".")
                    subresult = {}
                    for name in reversed(keys):
                        subresult = {name: subresult}
                try:
                    del results[subresult]
                    try:
                        self.es.index(index=self.index_name, doc_type="analysis", id=results["info"]["id"], body=report)
                        error_saved = False
                    except Exception as cept:
                        log.error("Failed to save results: %s", cept)
                except KeyError as cept:
                    log.error("Failed to delete key: %s", subresult)
                    error_saved = False


