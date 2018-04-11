import time
import os
import shutil
import logging
from threading import Thread

from lib.api.process import Process
from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)


class Auxfile(Auxiliary):
    """Create an empty file in supplied path, %TEMP% by default"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)

    def start(self):
        auxfile = self.options.get("auxfile")
        auxpath = self.options.get("auxpath")
        auxtxt = self.options.get("auxtxt")

        if not auxfile:
            return True

        if not auxpath:
            basepath = os.getenv('TEMP')
            newfile = os.path.join(basepath, auxfile)
        else:
            newfile = os.path.join(auxpath, auxfile)

        try:
            if auxtxt:
                with open(newfile, 'w+') as auxf:
                    auxf.write(auxtxt)
            else:
                with open(newfile, 'w+'): pass
            return True
        except Exception as err:
            log.exception(err)
            return False