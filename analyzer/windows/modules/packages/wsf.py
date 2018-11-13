# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class WSF(Package):
    """Windows Scripting File analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")
        return self.execute(wscript, "\"%s\"" % path, path)
