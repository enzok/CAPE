import os
import shutil
import logging
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.utils import get_memdump_path

log = logging.getLogger(__name__)
reporting_conf = Config("reporting")


class Savememdmp(Report):
    """Save RAMFS memdump files"""
    order = 10001

    def run(self, results):
        if "options" in results["info"] and "save_memory" in results["info"]["options"]:
            zipmemdump = self.options.get("zipmemdump", False)
            task_id = results["info"]["id"]
            src = get_memdump_path(task_id)
            dest = get_memdump_path(task_id, analysis_folder=True)

            if zipmemdump:
                src += ".zip"
                dest += ".zip"

            log.debug("Saving memdump: {} to {}".format(src, dest))
            if os.path.exists(src):
                shutil.move(src, dest)
