import os
import json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class MiniJson(Report):
    """Saves a subset of analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")
        ram_boost = self.options.get("ram_boost", True)

        try:
            miniresults = {}
            if 'file' in results['target']:
                miniresults['file'] = results['target']['file']
            if 'malfamily' in results:
                miniresults['malfamily'] = results['malfamily']
            if 'signatures' in results:
                miniresults['signatures'] = results['signatures']
            if 'dropped' in results:
                miniresults['dropped'] = results['dropped']
            if 'network' in results:
                miniresults['network'] = results['network']
            if 'permalink' in results['virustotal']:
                miniresults['virustotal'] = results['virustotal']['permalink']
            if 'mutexes' in results['behavior']['summary']:
                miniresults['mutexes'] = results['behavior']['summary']['mutexes']
            if 'executed_commands' in results['behavior']['summary']:
                miniresults['executed_commands'] = results['behavior']['summary']['executed_commands']

            path = os.path.join(self.reports_path, "report.json")
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
