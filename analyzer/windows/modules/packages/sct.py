# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package

class SCT(Package):
    """Sct analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
        ("SystemRoot", "system32", "regsvr32.exe"),
    ]

    def start(self, path):
        regsvr32 = self.get_path("regsvr32.exe")
        args = "{} /s /u /n /i:{} scrobj.dll".format(regsvr32, path)
        cmd_path = self.get_path("cmd.exe")
        cmd_args = "/c start /wait \"\" \"{0}\"".format(args)

        return self.execute(cmd_path, cmd_args, path)
