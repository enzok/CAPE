#
#
#

from lib.cuckoo.common.abstracts import Signature


class Office_Macro_Autoexec(Signature):
    name = "office_macro_autoexec"
    description = "Document contains auto-executable macros."
    severity = 3
    categories = ["office"]
    authors = ["enzok"]
    minimum = "1.3"

    def run(self):
        ret = False
        if "static" in self.results and "office" in self.results["static"]:
            # 97-2003 OLE and 2007+ XML macros
            if "Macro" in self.results["static"]["office"]:
                if "AutoExec" in self.results["static"]["office"]["Analysis"]:
                    ret = True
                for func, desc in self.results["static"]["office"]["Analaysis"]["AutoExec"]:
                    self.data.append({func: desc})

        return ret
