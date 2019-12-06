import os
import shutil
import logging
from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class Exe(Package):
    """EXE analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]


    def start(self, path):
        wwwroot = self.options.get("wwwroot", "")

        # copy the webshell to specified directory
        if not wwwroot:
            wwwroot = os.path.join("inetpub", "wwwroot")
        basepath = os.getenv('SystemDrive')
        newpath = os.path.join(basepath, wwwroot, os.path.basename(path))
        log.info("newpath =  {}".format(newpath))
        shutil.copy(path, newpath)
        path = ""
        cmd_path = self.get_path("cmd.exe")
        cmd_args = "/c start /wait dir \"\" \"{0}\"".format(newpath)
        return self.execute(cmd_path, cmd_args, path)
