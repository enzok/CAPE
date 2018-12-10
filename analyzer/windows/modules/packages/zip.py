# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import logging

try:
    import re2 as re
except ImportError:
    import re

from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

from _winreg import (OpenKey, CreateKeyEx, SetValueEx, CloseKey, QueryInfoKey, EnumKey,
        EnumValue, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, KEY_SET_VALUE, KEY_READ,
        REG_SZ, REG_DWORD)

log = logging.getLogger(__name__)

class Zip(Package):
    """Zip analysis package."""
    PATHS = [
             ("SystemRoot", "system32", "cmd.exe"),
             ("SystemRoot", "system32", "wscript.exe"),
             ("SystemRoot", "system32", "rundll32.exe"),
            ]

    def filtered_namelist(self, archive):
        return [x for x in archive.namelist() if x]

    def extract_zip(self, zip_path, extract_path, password, recursion_depth):
        """Extracts a nested ZIP file.
        @param zip_path: ZIP path
        @param extract_path: where to extract
        @param password: ZIP password
        @param recursion_depth: how deep we are in a nested archive
        """
        # Test if zip file contains a file named as itself.
        if self.is_overwritten(zip_path):
            log.debug("ZIP file contains a file with the same name, original is going to be overwrite")
            # TODO: add random string.
            new_zip_path = zip_path + ".old"
            shutil.move(zip_path, new_zip_path)
            zip_path = new_zip_path

        # Extraction.
        with ZipFile(zip_path, "r") as archive:
            try:
                archive.extractall(path=extract_path, members=self.filtered_namelist(archive), pwd=password)
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, members=self.filtered_namelist(archive), pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file: "
                                             "{0}".format(e))
            finally:
                if recursion_depth < 4:
                    # Extract nested archives.
                    for name in self.filtered_namelist(archive):
                        if name.endswith(".zip"):
                            # Recurse.
                            try:
                                self.extract_zip(os.path.join(extract_path, name), extract_path, password,
                                                 recursion_depth + 1)
                            except BadZipfile:
                                log.warning("Nested zip file '%s' name end with 'zip' extension \\"
                                            "is not a valid zip. Skip extracting" % name)
                            except RuntimeError as run_err:
                                log.error("Error to extract nested zip file %s with details: %s" % name, run_err)

    def is_overwritten(self, zip_path):
        """Checks if the ZIP file contains another file with the same name, so it is going to be overwritten.
        @param zip_path: zip file path
        @return: comparison boolean
        """
        with ZipFile(zip_path, "r") as archive:
            try:
                # Test if zip file contains a file named as itself.
                for name in self.filtered_namelist(archive):
                    if name == os.path.basename(zip_path):
                        return True
                return False
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")

    def get_infos(self, zip_path):
        """Get information from ZIP file.
        @param zip_path: zip file path
        @return: ZipInfo class
        """
        try:
            with ZipFile(zip_path, "r") as archive:
                return archive.infolist()
        except BadZipfile:
            raise CuckooPackageError("Invalid Zip file")

    def set_keys(self):

        baseOfficeKeyPath = r"Software\Microsoft\Office"
        installedVersions = list()
        try:
            officeKey = OpenKey(HKEY_CURRENT_USER, baseOfficeKeyPath, 0, KEY_READ)
            for currentKey in xrange(0, QueryInfoKey(officeKey)[0]):
                isVersion = True
                officeVersion = EnumKey(officeKey, currentKey)
                if "." in officeVersion:
                    for intCheck in officeVersion.split("."):
                        if not intCheck.isdigit():
                            isVersion = False
                            break

                    if isVersion:
                        installedVersions.append(officeVersion)
            CloseKey(officeKey)
        except WindowsError:
            # Office isn't installed at all
            return

        for oVersion in installedVersions:
            key = CreateKeyEx(HKEY_CURRENT_USER,
                              r"{0}\{1}\Publisher\Security".format(baseOfficeKeyPath, oVersion),
                              0, KEY_SET_VALUE)

            SetValueEx(key, "VBAWarnings", 0, REG_DWORD, 1)
            SetValueEx(key, "AccessVBOM", 0, REG_DWORD, 1)
            SetValueEx(key, "ExtensionHardening", 0, REG_DWORD, 0)
            CloseKey(key)

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get("password")
        exe_regex = re.compile('(\.exe|\.dll|\.scr|\.msi|\.bat|\.lnk|\.js|\.jse|\.vbs|\.vbe|\.wsf)$',
                               flags=re.IGNORECASE)
        office_regex = re.compile('(\.doc|\.xls|\.pub|\.ppt)$', flags=re.IGNORECASE)
        zipinfos = self.get_infos(path)
        self.extract_zip(path, root, password, 0)

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # No name provided try to find a better name.
            if len(zipinfos):
                # Attempt to find a valid exe extension in the archive
                for f in zipinfos:
                    if exe_regex.search(f.filename):
                        file_name = f.filename
                        break
                    elif office_regex.search(f.filename):
                        file_name = f.filename
                        break
                # Default to the first one if none found
                file_name = file_name if file_name else zipinfos[0].filename
                log.debug("Missing file option, auto executing: {0}".format(file_name))
            else:
                raise CuckooPackageError("Empty ZIP archive")

        file_path = os.path.join(root, file_name)
        log.debug("file_name: \"%s\"" % (file_name))
        if file_name.lower().endswith(".lnk"):
            cmd_path = self.get_path("cmd.exe")
            cmd_args = "/c start /wait \"\" \"{0}\"".format(file_path)
            return self.execute(cmd_path, cmd_args, file_path)
        elif file_name.lower().endswith(".msi"):
            msi_path = self.get_path("msiexec.exe")
            msi_args = "/I \"{0}\"".format(file_path)
            return self.execute(msi_path, msi_args, file_path)
        elif file_name.lower().endswith((".js", ".jse", ".vbs", ".vbe", ".wsf")):
            wscript = self.get_path_app_in_path("wscript.exe")
            wscript_args = "\"{0}\"".format(file_path)
            return self.execute(wscript, wscript_args, file_path)
        elif file_name.lower().endswith(('.doc', 'docx', 'docm')):
            self.PATHS = [
                     ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
                     ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
                     ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
                     ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
                    ]
            word = self.get_path_glob("Microsoft Office Word")
            return self.execute(word, "\"%s\" /q" % file_path, file_path)
        elif file_name.lower().endswith(('.xls', 'xlsx', 'xlsb', 'xlsm')):
            self.PATHS = [
                     ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
                     ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
                     ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
                    ]
            excel = self.get_path_glob("Microsoft Office Excel")
            return self.execute(excel, "\"%s\" /e" % file_path, file_path)
        elif file_name.lower().endswith(('.ppt', 'pptx', 'pptm')):
            self.PATHS = [
                     ("ProgramFiles", "Microsoft Office", "POWERPNT.EXE"),
                     ("ProgramFiles", "Microsoft Office", "Office*", "POWERPNT.EXE"),
                     ("ProgramFiles", "Microsoft Office*", "root", "Office*", "POWERPNT.EXE"),
                    ]
            powerpoint = self.get_path_glob("Microsoft Office PowerPoint")
            return self.execute(powerpoint, "/s \"%s\"" % file_path, file_path)
        elif file_name.lower().endswith('.pub'):
            self.PATHS = [
                     ("ProgramFiles", "Microsoft Office", "MSPUB.EXE"),
                     ("ProgramFiles", "Microsoft Office", "Office*", "MSPUB.EXE"),
                     ("ProgramFiles", "Microsoft Office*", "root", "Office*", "MSPUB.EXE"),
                     ("ProgramFiles", "Microsoft Office", "MSPUB.EXE"),
                    ]
            self.set_keys()
            publisher = self.get_path_glob("Microsoft Office Publisher")
            return self.execute(publisher, "/o \"%s\"" % file_path, file_path)
        elif file_name.lower().endswith(".dll"):
            rundll32 = self.get_path_app_in_path("rundll32.exe")
            function = self.options.get("function", "#1")
            arguments = self.options.get("arguments")
            loadername = self.options.get("loader")
            dll_args = "\"{0}\",{1}".format(file_path, function)
            if arguments:
                dll_args += " {0}".format(arguments)
            if loadername:
                newname = os.path.join(os.path.dirname(rundll32), loadername)
                shutil.copy(rundll32, newname)
                rundll32 = newname
            return self.execute(rundll32, dll_args, file_path)
        else:
            return self.execute(file_path, self.options.get("arguments"), file_path)

