import os
import logging

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class Cmstp(Package):
    """Cmstp analysis package."""
    PATHS = [
             ("SystemRoot", "system32", "cmstp.exe"),
            ]

    def _create_inf(self, target):
        inf_file = "cmstp.inf"
        root = os.environ["TEMP"]
        file_path = os.path.join(root, inf_file)
        with open(file_path, "w") as inf:
            inf.write('[version]\nSignature=$chicago$\nAdvancedINF=2.5\n\n')
            inf.write("[DefaultInstall_SingleUser]\nUnRegisterOCXs=UnRegisterOCXSection\n\n")
            inf.write("[[UnRegisterOCXSection]\n%11%\scrobj.dll,NI,%Filename%\n\n")
            inf.write('[Strings]\nFilename="{}"\nServiceName="BONG"\nShortSvcName="BONG"\n'.format(target))

        if os.path.exists(file_path):
            log.info("{} created.".format(file_path))
        else:
            return False

        return file_path

    def start(self, path):
        file_path = self._create_inf(path)
        if file_path:
            cmstp = self.get_path("cmstp.exe")
            if 'PROGRAMFILES(X86)' in os.environ:
                cmstp = cmstp.replace("system32", "syswow64")
            cmstp_args = "/s /ns {}".format(file_path)

            return self.execute(cmstp, cmstp_args, file_path)
        else:
            raise CuckooPackageError("INF file was not created")