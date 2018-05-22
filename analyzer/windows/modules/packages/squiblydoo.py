# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package

class SQUIBLYDOO(Package):
    """Squiblydoo analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "regsvr32.exe"),
    ]

    def start(self, path):
        regsvr32 = self.get_path("regsvr32.exe")
        arguments = self.options.get("arguments")

        if arguments:
            args = '{0} /i:\"{1}\" scrobj.dll'.format(arguments, path)
        else:
            args = '/i:\"{0}\" scrobj.dll'.format(path)

        return self.execute(regsvr32, args, path)
