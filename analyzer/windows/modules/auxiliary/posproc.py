import os
import logging
from threading import Thread
from time import sleep

from lib.api.process import Process
from lib.common.abstracts import Auxiliary
from lib.core.config import Config

log = logging.getLogger(__name__)


class POSFaker(Auxiliary):
    """ Start a process to generate track 1 or 2 data in supplied process
        Make sure gencc.exe is included in the analyzer bin directory
        https://github.com/bizdak/ccgen
    """

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")
        self.enabled = self.config.posproc

    def start(self):
        if not self.enabled:
            return True

        try:
            posproc = self.options.get("posproc", None)
            if not posproc:
                log.info("Skipping POSFaker executable: not configureed.")
                return True

            posname = self.options.get("posname")

            if posname:
                pos_path = os.path.join(os.getcwd(), "bin", "ccgen.exe")
                if not os.path.exists(pos_path):
                    log.info("Skipping POSFaker, ccgen.exe was not found in bin/")
                    return True

                newpath = os.path.join(os.getcwd(), "bin", posname)

                try:
                    os.rename(pos_path, newpath)
                    path = newpath
                    sleep(1)
                except Exception as e:
                    log.error("Failed to rename {} to {}: {}".format(pos_path, newpath, e))
                    return False

            cmd_args = "/k start /min \"\" \"{0} -2 -s 69 -d 500\"".format(path)
            pos = Process()
            cmd_path = os.getenv("ComSpec")
            pos.execute(path=cmd_path, args=cmd_args, suspended=False)
            log.info("Fake POS process started: {} {}".format(cmd_path, cmd_args))
            sleep(5)

        except Exception:
            import traceback
            log.exception(traceback.format_exc())

        return True