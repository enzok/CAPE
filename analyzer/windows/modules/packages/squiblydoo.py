# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package

class SQUIBLYDOO(Package):
    """Squiblydoo analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

    def start(self, path):
        cmd_path = self.get_path("cmd.exe")
        cmd_args = "/c start /wait \"\" regsvr32.exe /s /u /n /i:\"{}\" scrobj.dll".format(path)

        return self.execute(cmd_path, cmd_args, path)