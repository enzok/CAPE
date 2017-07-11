import logging
import os

from lib.common.abstracts import Package

log = logging.getLogger(__name__)


class ODBCCONF(Package):
    """Odbcconf.exe regsvr analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "odbcconf.exe"),
    ]

    def start(self, path):
        odbcconf = self.get_path("odbcconf.exe")

        if not path.endswith("dll"):
            os.rename(path, path + ".dll")
            path += ".dll"

        return self.execute(odbcconf, "/A {REGSVR \"%s\"}" % path, path)
