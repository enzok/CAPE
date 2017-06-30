# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from lib.common.abstracts import Package
from _winreg import HKEY_CURRENT_USER


class XLS(Package):
    """Excel analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
    ]

    REGKEYS = [
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Office\\12.0\\Common\\General",
            {
                # "Welcome to the 2007 Microsoft Office system"
                "ShownOptIn": 1,
            },
        ],
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Office\\12.0\\Excel\\Security",
            {
                # Enable VBA macros in Office 2007.
                "VBAWarnings": 1,
                "AccessVBOM": 1,

                # "The file you are trying to open .xyz is in a different
                # format than specified by the file extension. Verify the file
                # is not corrupted and is from trusted source before opening
                # the file. Do you want to open the file now?"
                "ExtensionHardening": 0,
            },
        ],
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Office\\Common\\Security",
            {
                # Enable all ActiveX controls without restrictions & prompting.
                "DisableAllActiveX": 0,
                "UFIControls": 1,
            },
        ],
    ]

    def start(self, path):
        excel = self.get_path_glob("Microsoft Office Excel")

        if not path.endswith((".xls", ".xlsx", ".xlsm")):
            os.rename(path, path + ".xls")
            path += ".xls"

        return self.execute(excel, "\"%s\" /e" % path, path)
