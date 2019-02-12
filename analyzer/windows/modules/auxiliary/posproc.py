import os
import logging
from threading import Thread

from lib.api.process import Process
from lib.common.abstracts import Auxiliary
from lib.core.config import Config

log = logging.getLogger(__name__)


class POSfaker(Auxiliary, Thread):
    """ Start a process to generate track 1 or 2 data in supplied process
        Make sure gencc.exe is included in the analyzer bin directory
        https://github.com/bizdak/ccgen
    """

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = Config(cfg="analysis.conf")
        self.enabled = self.config.posproc
        self.do_run = self.enabled
        self.path = self.config.posproc.get("path", None)

    def stop(self):
        if self.enabled:
            self.do_run = False
            return True
        return False

    def run(self):
        if not self.enabled or not self.path:
            return False

        posproc = self.options.get("posproc")

        if posproc:
            newpath = os.path.join("bin", posproc)

            try:
                os.rename(self.path, newpath)
                self.path = newpath
            except IOError as e:
                log.error("Failed to rename {} to {}: {}".format(self.path, newpath, e))
                return False

        cmd_args = "/k start /min \"\" \"{0} -2 -s 69 -d 500\"".format(self.path)
        pos = Process()
        cmd_path = os.getenv("ComSpec")
        pos.execute(path=cmd_path, args=cmd_args, suspended=False)
        return True
