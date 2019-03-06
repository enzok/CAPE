import os
import shutil
import logging
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)
reporting_conf = Config("reporting")


class Savememdmp(Report):
    """Save RAMFS memdump files"""
    order = 10001

    def run(self, results):
        if "options" in results["info"] and "save_memory" in results["info"]["options"]:
            zipmemdump = self.options.get("zipmemdump", False)
            src = self.rmemory_path
            dest = self.memory_path

            if zipmemdump:
                src += ".zip"
                dest += ".zip"

            log.debug("Saving memdump: {} to {}".format(src, dest))
            try:
                if os.path.exists(src):
                    shutil.move(src, dest)
            except Exception as e:
                log.error("Failed to move memdump {} to {}: {}".format(src, dest, e))
