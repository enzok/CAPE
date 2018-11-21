# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
import os
import logging
from threading import Thread

from lib.api.process import Process
from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

PATHS = [
    ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
    ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
    ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
    ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
    ("SystemRoot", "system32", "cmd.exe"),
]

class OfficeWord(Auxiliary, Thread):
    """Launch a Microsoft Office minimized"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
        startword = self.options.get("startword")
        if not startword:
            return True

        while self.do_run:
            cmd_path = self.get_path_glob("cmd.exe")
            word = self.get_path_glob("Microsoft Office Word")
            cmd_args = "/c start /min \"\" \"{0}\"".format(word)
            word = Process()
            word.execute(path=cmd_path, args=cmd_args, suspended=False)
            word.close()
