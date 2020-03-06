import os
import json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class MiniJson(Report):
    """Saves a subset of analysis results in JSON format."""

    order = 99990

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")
        ram_boost = self.options.get("ram_boost", True)

        try:
            report = dict(results)

            miniresults = dict()
            if 'file' in report['target']:
                miniresults['file'] = report['target']['file']
            if 'malfamily' in report:
                miniresults['malfamily'] = report['malfamily']
            if 'signatures' in report:
                miniresults['signatures'] = report['signatures']
            if 'dropped' in report:
                miniresults['dropped'] = report['dropped']
            if 'network' in report:
                miniresults['network'] = report['network']
            if 'virustotal'in report and 'permalink' in report['virustotal']:
                miniresults['virustotal'] = report['virustotal']['permalink']
            if 'mutexes' in report['behavior']['summary']:
                miniresults['mutexes'] = report['behavior']['summary']['mutexes']
            if 'encryptedbuffers' in report['behavior']:
                miniresults['encryptedbuffers'] = report['behavior']['encryptedbuffers']
            if 'executed_commands' in report['behavior']['summary']:
                miniresults['executed_commands'] = report['behavior']['summary']['executed_commands']
            if "suricata" in report and report["suricata"]:
                if "tls" in report["suricata"] and len(report["suricata"]["tls"]) > 0:
                    miniresults["suri_tls_cnt"] = len(report["suricata"]["tls"])
                if "alerts" in report["suricata"] and len(report["suricata"]["alerts"]) > 0:
                    miniresults["suri_alert_cnt"] = len(report["suricata"]["alerts"])
                if "files" in report["suricata"] and len(report["suricata"]["files"]) > 0:
                    miniresults["suri_file_cnt"] = len(report["suricata"]["files"])
                if "http" in report["suricata"] and len(report["suricata"]["http"]) > 0:
                    miniresults["suri_http_cnt"] = len(report["suricata"]["http"])

            path = os.path.join(self.reports_path, "mini-report.json")
            with codecs.open(path, "w", "utf-8") as report:
                if ram_boost:
                    buf = json.dumps(miniresults, sort_keys=False,
                              indent=int(indent), encoding=encoding)
                    report.write(buf)
                else:
                    json.dump(miniresults, report, sort_keys=False,
                              indent=int(indent), encoding=encoding)
        except (UnicodeError, TypeError, IOError, KeyError) as e:
            raise CuckooReportError("Failed to generate mini JSON report: %s" % e)
