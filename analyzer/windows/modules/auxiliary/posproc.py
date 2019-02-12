import os
import logging
from threading import Thread

from lib.api.process import Process
from lib.common.abstracts import Auxiliary
from lib.core.config import Config

log = logging.getLogger(__name__)


class POSFaker(Auxiliary, Thread):
    """ Start a process to generate track 1 or 2 data in supplied process
        Make sure gencc.exe is included in the analyzer bin directory
        https://github.com/bizdak/ccgen
    """

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = Config(cfg="analysis.conf")
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
        enabled = self.config.posproc
        posproc = self.options.get("posproc", None)
        path = self.config.posproc.get("path", None)
        if not enabled and not posproc and not path:
            return True

        posname = self.options.get("posname")

        if posname:
            newpath = os.path.join("bin", posname)

            try:
                os.rename(path, newpath)
                path = newpath
            except IOError as e:
                log.error("Failed to rename {} to {}: {}".format(path, newpath, e))
                return False

        if self.do_run:
            cmd_args = "/k start /min \"\" \"{0} -2 -s 69 -d 500\"".format(path)
            pos = Process()
            cmd_path = os.getenv("ComSpec")
            pos.execute(path=cmd_path, args=cmd_args, suspended=False)
            log.info("Fake POS process started: {} {}".format(cmd_path, cmd_args))
