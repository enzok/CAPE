# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shutil
import logging

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class IE(Package):
    """Internet Explorer analysis package."""
    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def start(self, path):
        iexplore = self.get_path("Internet Explorer")

        if not path.endswith((".swf")):
            shutil.copy(path, path + ".swf")
            path += ".swf"
            log.info("Submitted file is missing extension, adding .swf")

        return self.execute(iexplore, "\"%s\"" % path, path)
