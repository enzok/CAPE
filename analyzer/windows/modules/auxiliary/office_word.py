# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import glob
import logging
from threading import Thread

from lib.api.process import Process
from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)


CMDPATHS = [
    ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
    ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
    ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
    ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
]

WORDPATHS = [
    ("SystemRoot", "system32", "cmd.exe"),
]

class OfficeWord(Auxiliary, Thread):
    """Launch a Microsoft Office minimized"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.do_run = True
        self.PATHS = []

    def stop(self):
        self.do_run = False

    def enum_paths(self):
        """Enumerate available paths."""
        for path in self.PATHS:
            basedir = path[0]
            if basedir == "SystemRoot":
                yield os.path.join(os.getenv("SystemRoot"), *path[1:])
            elif basedir == "ProgramFiles":
                if os.getenv("ProgramFiles(x86)"):
                    yield os.path.join(os.getenv("ProgramFiles(x86)"),
                                       *path[1:])
                yield os.path.join(os.getenv("ProgramFiles").replace(" (x86)", ""), *path[1:])
            elif basedir == "HomeDrive":
                # os.path.join() does not work well when giving just C:
                # instead of C:\\, so we manually add the backslash.
                homedrive = os.getenv("HomeDrive") + "\\"
                yield os.path.join(homedrive, *path[1:])
            else:
                yield os.path.join(*path)

    def get_path(self, paths):
        """Search for the application in all available paths.
        @param application: application executable name
        @return: executable path
        """
        self.PATHS = paths
        for path in self.enum_paths():
            if os.path.isfile(path):
                return path

    def get_path_glob(self, paths):
        """Search for the application in all available paths with glob support.
        @param application: application executable name
        @return: executable path
        """
        self.PATHS = paths
        for path in self.enum_paths():
            for path in glob.iglob(path):
                if os.path.isfile(path):
                    return path

    def run(self):
        startword = self.options.get("startword")
        if not startword:
            return True

        while self.do_run:
            cmd_path = self.get_path_glob(CMDPATHS)
            word = self.get_path_glob(WORDPATHS)
            cmd_args = "/c start /min \"\" \"{0}\"".format(word)
            word = Process()
            log.info("Launching Word with {} {}".format(cmd_path, cmd_args))
            word.execute(path=cmd_path, args=cmd_args, suspended=False)
