<<<<<<< HEAD
# Copyright (C) 2014 enzok
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
=======
#
#
#
>>>>>>> f179decd964735bfaed1ea6366143ba47fc17036

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
<<<<<<< HEAD
=======
            # 97-2003 OLE and 2007+ XML macros
>>>>>>> f179decd964735bfaed1ea6366143ba47fc17036
            if "Macro" in self.results["static"]["office"]:
                if "AutoExec" in self.results["static"]["office"]["Macro"]["Analysis"]:
                    ret = True
                for func, desc in self.results["static"]["office"]["Macro"]["Analysis"]["AutoExec"]:
                    self.data.append({func: desc})

        return ret
