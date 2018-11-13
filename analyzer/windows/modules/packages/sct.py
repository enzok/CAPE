# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package

class SCT(Package):
    """Sct analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")

        # Enforce the .wsf file extension as is required by wscript.
        if not path.endswith(".wsf"):
            os.rename(path, path + ".js")
            path += ".js"

        return self.execute(wscript, "\"%s\"" % path, path)
