import os
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class MinitextSummary(Report):
    """Saves a subset of analysis results in text format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        outbuf = ""
        host_filter = ["8.8.8.8",
                       "8.8.4.4",
                       "time.windows.com",
                       "teredo.ipv6.microsoft.com",
                       "www.download.windowsupdate.com",
                       "acroipm2.adobe.com",
                       "acroipm.adobe.com",
                       "files.acrobat.com",
                       "ctldl.windowsupdate.com"]

        try:
            if 'malfamily' in results:
                outbuf += "Malfamily - " + results['malfamily'] + "\n\n"
            else:
                outbuf += "Malfamily - unknown \n\n"

            if 'file' in results['target']:
                outbuf += "Name: " + results['target']['file']['name'] + "\n"
                outbuf += "MD5: " + results['target']['file']['md5'] + "\n"
                outbuf += "SHA1: " + results['target']['file']['sha1'] + "\n"
                outbuf += "SHA256: " + results['target']['file']['sha256'] + "\n"
                outbuf += "ssdeep: " + results['target']['file']['ssdeep'] + "\n\n"

            if 'signatures' in results:
                outbuf += "Signatures -\n"
                for sig in results['signatures']:
                    outbuf += "  " + sig['name'] + ": " + sig['description'] + "\n"
                outbuf += "\n"

            if 'executed_commands' in results['behavior']['summary']:
                outbuf += "Executed commands -\n"
                cmds = []
                for ec in results['behavior']['summary']['executed_commands']:
                    newcmd = ec.strip('"')
                    if newcmd not in cmds:
                        cmds.append(newcmd)
                for cmd in cmds:
                    outbuf += "  " + cmd + "\n"
                outbuf += "\n"

            if 'network' in results:
                outbuf += "Network -\n"
                outbuf += "  Hosts -\n"
                for host in results['network']['hosts']:
                    if host['ip'] in host_filter or host['hostname'] in host_filter:
                        continue
                    outbuf += "    " + host['hostname'] + ", " + host['inaddrarpa'] + ": "
                    outbuf += host['ip'] + " " + host['country_name'] + "\n"
                outbuf += "\n"
                outbuf += "  HTTP -\n"
                for http in results['network']['http']:
                    outbuf += "    uri: " + http['uri'] + "\n"
                    outbuf += "    data: " + http['data'].replace("\r\n", "\n          ")
                outbuf += "\n"
                outbuf += "  SMTP -\n"
                for smtp in results['network']['smtp']:
                    outbuf += "    dst: " + smtp['dst'] + "\n"
                    tmpdata = smtp['raw'].replace("\r\n", "\n          ")
                    tmpdata = tmpdata.replace("\n\\", "\n          \\")
                    tmpdata = tmpdata.replace("\r", "\r          ")
                    outbuf += "    data: " + tmpdata + "\n"
                outbuf += "\n"

            outbuf.replace("http:", "hxxp:")
            outbuf.replace("HTTP:", "HXXP:")
            outbuf.replace("www.", "www[.]")

            path = os.path.join(self.reports_path, "minitext-report.txt")
            with codecs.open(path, "w", "utf-8") as report:
                report.write(outbuf)

        except (UnicodeError, TypeError, IOError, KeyError) as e:
            raise CuckooReportError("Failed to generate summary text report: %s" % e)

