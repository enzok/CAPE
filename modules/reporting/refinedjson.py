import os
import json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.core.database import Database, Task


class RefinedJson(Report):
    """Saves a subset of analysis results in JSON format."""

    order = 99993

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")
        ram_boost = self.options.get("ram_boost", True)

        host_filter = ["8.8.8.8",
                       "8.8.4.4",
                       "time.windows.com",
                       "teredo.ipv6.microsoft.com",
                       "ie9cvlist.ie.microsoft.com",
                       "www.download.windowsupdate.com",
                       "acroipm2.adobe.com",
                       "acroipm.adobe.com",
                       "files.acrobat.com",
                       "ctldl.windowsupdate.com"]

        try:
            db = Database()
            report = dict(results)

            miniresults = dict()
            if 'file' in report['target']:
                miniresults['file'] = report['target']['file']
                del miniresults['file']['yara']
                del miniresults['file']['path']
                del miniresults['file']['guest_paths']
                miniresults['file']['yara'] = []
                for rule in report['target']['file']['yara']:
                    miniresults['file']['yara'].append({'name': rule['name']})
            if 'malfamily' in report:
                miniresults['malfamily'] = report['malfamily']
            if 'signatures' in report:
                miniresults['signatures'] = []
                for sig in report['signatures']:
                    miniresults['signatures'].append({'description': sig['description']})
            if 'network' in report:
                net = report['network']
                mininet = dict()
                mininet['hosts'] = []
                for host in net['hosts']:
                    if host['ip'] in host_filter or host['hostname'] in host_filter:
                        continue
                    mininet['hosts'].append(host)
                mininet['http'] = []
                for http in net['http']:
                    if http['host'] in host_filter:
                        continue
                    httpdict = http
                    httpdict['uri'] = http['uri']
                    httpdict['data'] = http['data']
                    mininet['http'].append(httpdict)
                mininet['smtp'] = net['smtp']
                mininet['irc'] = net['irc']

                '''
                if "suricata" in report and report["suricata"]:
                    if "alerts" in report["suricata"] and len(report["suricata"]["alerts"]) > 0:
                        mininet["alerts"] = report["suricata"]["alerts"]
                    if "http" in report["suricata"] and len(report["suricata"]["http"]) > 0:
                        mininet["suri_http"] = report["suricata"]["http"]
                '''

                miniresults['network'] = mininet
            if 'executed_commands' in report['behavior']['summary']:
                miniresults['executed_commands'] = report['behavior']['summary']['executed_commands']

            session = db.Session()
            task_id = report['info']['id']
            children = [c for c in session.query(Task.id, Task.package).filter(Task.parent_id == task_id)]

            if children:
                miniresults['cape'] = dict()
                cape = miniresults['cape']
                cape['parent_id'] = task_id
                cape['children'] = []
                for kid in children:
                    child = dict()
                    child['task_id'], child['type'] = kid
                    cape['children'].append(child)

            path = os.path.join(self.reports_path, "refined-report.json")
            with codecs.open(path, "w", "utf-8") as report:
                if ram_boost:
                    buf = json.dumps(miniresults, sort_keys=False, indent=int(indent), encoding=encoding)
                    report.write(buf)
                else:
                    json.dump(miniresults, report, sort_keys=False, indent=int(indent), encoding=encoding)
        except (UnicodeError, TypeError, IOError, KeyError) as e:
            raise CuckooReportError("Failed to generate refined JSON report: %s" % e)
