import os
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class TextSummary(Report):
    """Saves a subset of analysis results in text format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        outbuf = ""

        try:
            if 'permalink' in results['virustotal']:
                outbuf += "Virus Total: " + results['virustotal']['permalink'] + "\n"
            else:
                outbuf += "Virus Total: None\n\n"

            if 'file' in results['target']:
                outbuf += "Name: " + results['target']['file']['name'] + "\n"
                outbuf += "MD5: " + results['target']['file']['md5'] + "\n"
                outbuf += "SHA1: " + results['target']['file']['sha1'] + "\n"
                outbuf += "SHA256: " + results['target']['file']['sha256'] + "\n"
                outbuf += "ssdeep: " + results['target']['file']['ssdeep'] + "\n\n"

                outbuf += "Yara signature:\n"
                for sig in results['target']['file']['yara']:
                    outbuf += "  " + sig['name'] + "\n"
                outbuf += "\n"

            if 'malfamily' in results:
                outbuf += "Malfamily: " + results['malfamily'] + "\n\n"
            else:
                outbuf += "Malfamily: unknown \n\n"

            if 'signatures' in results:
                outbuf += "Signatures: \n"
                for sig in results['signatures']:
                    outbuf += "  " + sig['name'] + ": " + sig['description'] + "\n"
                outbuf += "\n"

            if 'dropped' in results:
                outbuf += "Dropped:\n"
                for drop in results['dropped']:
                    outbuf += "  Name: " + drop['name'] + "\n"
                    outbuf += "  MD5: " + drop['md5'] + "\n"
                    outbuf += "  SHA1: " + drop['sha1'] + "\n"
                    outbuf += "  SHA256: " + drop['sha256'] + "\n"
                    outbuf += "  ssdeep: " + drop['ssdeep'] + "\n"
                    outbuf += "  file type: " + drop['type'] + "\n"
                    if len(drop['yara']) > 0:
                        outbuf += "  Yara signature:\n"
                        for sig in drop['yara']:
                            outbuf += "    " + sig['name'] + "\n"
                    outbuf += "\n"
                outbuf += "\n"

            if 'executed_commands' in results['behavior']['summary']:
                outbuf += "Executed commands:\n"
                for ec in results['behavior']['summary']['executed_commands']:
                    outbuf += "  " + ec + "\n"
                outbuf += "\n"

            if 'mutexes' in results['behavior']['summary']:
                outbuf += "mutexes:\n"
                for mutex in results['behavior']['summary']['mutexes']:
                    outbuf += "  " + mutex + "\n"
                outbuf += "\n"

            if 'network' in results:
                outbuf += "Network:\n"
                outbuf += "  DNS:\n"
                for dns in results['network']['dns']:
                    outbuf += "    " + dns['request'] + ": "
                    for rec in dns['answers']:
                        outbuf += rec['data'] + " "
                    outbuf += "\n"
                outbuf += "\n"
                outbuf += "  Domains:\n"
                for dom in results['network']['domains']:
                    outbuf += "    " + dom['domain'] + ": " + dom['ip'] + "\n"
                outbuf += "\n"
                outbuf += "  Hosts:\n"
                for host in results['network']['hosts']:
                    outbuf += "    " + host['hostname'] + ": " + host['ip'] + " " + host['country_name'] + "\n"
                outbuf += "\n"
                outbuf += "  ICMP:\n"
                for icmp in results['network']['icmp']:
                    outbuf += "    dst: " + icmp['dst'] + ", data: " + icmp['data'] + "\n"
                outbuf += "\n"
                outbuf += "  TCP:\n"
                for tcp in results['network']['tcp']:
                    outbuf += "    sPort: " + str(tcp['sport']) + \
                              "\n    dst: " + tcp['dst'] + ":" + str(tcp['dport']) + "\n"
                outbuf += "\n"
                outbuf += "  UDP:\n"
                for udp in results['network']['udp']:
                    outbuf += "    sPort: " + str(udp['sport']) + \
                              "\n    dst: " + udp['dst'] + ":" + str(udp['dport']) + "\n"
                outbuf += "\n"
                outbuf += "  HTTP:\n"
                for http in results['network']['http']:
                    outbuf += "    uri: " + http['uri'] + "\n"
                    outbuf += "    data: " + http['data'].replace("\r\n", "\n          ")
                outbuf += "  SMTP:\n"
                for smtp in results['network']['smtp']:
                    outbuf += "    dst: " + smtp['dst'] + "\n"
                    tmpdata = smtp['raw'].replace("\r\n", "\n          ")
                    tmpdata = tmpdata.replace("\n\\", "\n          \\")
                    tmpdata = tmpdata.replace("\r", "\r          ")
                    outbuf += "    data: " + tmpdata + "\n"
                outbuf += "\n"

            path = os.path.join(self.reports_path, "summary-report.txt")
            with codecs.open(path, "w", "utf-8") as report:
                report.write(outbuf)

        except (UnicodeError, TypeError, IOError, KeyError) as e:
            raise CuckooReportError("Failed to generate summary text report: %s" % e)

