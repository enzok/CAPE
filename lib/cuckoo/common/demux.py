# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
import logging

try:
    from rarfile import RarFile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

try:
    from sflock import unpack
    from sflock.unpack.office import OfficeFile
    from sflock.abstracts import File as sfFile
    HAS_SFLOCK = True
except ImportError:
    print("Warning: sflock not installed; archives will not be handled.\n"\
    "sudo apt-get install p7zip-full rar unace-nonfree cabextract\n"\
    "pip install -U sflock")
    HAS_SFLOCK = False


from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooDemuxError

logging.basicConfig()
log = logging.getLogger(__name__)

demux_extensions_list = [
        "", ".exe", ".dll", ".com", ".jar", ".pdf", ".msi", ".bin", ".scr", ".zip", ".tar", ".gz", ".tgz", ".rar",
        ".doc", ".dot", ".docx", ".dotx", ".docm", ".dotm", ".docb", ".mht", ".mso", ".js", ".jse", ".vbs", ".vbe",
        ".xls", ".xlt", ".xlm", ".xlsx", ".xltx", ".xlsm", ".xltm", ".xlsb", ".xla", ".xlam", ".xll", ".xlw", ".htm",
        ".ppt", ".pot", ".pps", ".pptx", ".pptm", ".potx", ".potm", ".ppam", ".ppsx", ".ppsm", ".sldx", ".sldm", ".wsf",
        ".html", ".hta",
    ]

office_pkgs = ["doc", "xls", "ppt", "pub"]


# list of valid file types to extract - TODO: add more types
VALID_TYPES = ["PE32", "Java Jar", "Outlook", "Message"]


def options2passwd(options):
    password = False
    if "password=" in options:
        fields = options.split(",")
        for field in fields:
            try:
                key, value = field.split("=", 1)
                if key == "password":
                    password = value
                    break
            except:
                pass

    return password


def demux_office(filename, password):
    retlist = []

    options = Config()
    tmp_path = options.cuckoo.get("tmppath", "/tmp")

    basename = os.path.basename(filename)
    target_path = os.path.join(tmp_path, "cuckoo-tmp/msoffice-crypt-tmp")
    if not os.path.exists(target_path):
        os.mkdir(target_path)
    decrypted_name = os.path.join(target_path, basename)

    if HAS_SFLOCK:
        ofile = OfficeFile(sfFile.from_path(filename))
        d = ofile.decrypt(password)
        with open(decrypted_name, "w") as outs:
            outs.write(d.contents)
        # TODO add decryption verification checks
        if "Encrypted" not in d.magic:
            retlist.append(decrypted_name)
    else:
        raise CuckooDemuxError("MS Office decryptor not available")

    if not retlist:
        retlist.append(filename)

    return retlist


def is_valid_type(magic):
    # check for valid file types and don't rely just on file extentsion
    for ftype in VALID_TYPES:
        if ftype in magic:
            return True
    return False


def get_filenames(retlist, tmp_dir, children):
    try:
        for child in children:
            at = child.astree()
            magic = child.magic
            if 'file' in at['type'] or \
                    child.package in office_pkgs or \
                    ("Microsoft" in magic and not ("Outlook" in magic or "Message" in magic)):
                base, ext = os.path.splitext(at['filename'])
                ext = ext.lower()
                if ext in demux_extensions_list or is_valid_type(magic):
                    retlist.append(os.path.join(tmp_dir, at['filename'].encode('utf8', 'replace')))
            elif 'container' in at['type'] and child.package not in office_pkgs:
                get_filenames(retlist, tmp_dir, child.children)
    except Exception as err:
        log.error("Error getting file names: {}".format(err))

    return retlist


def demux_sflock(filename, options):
    retlist = []
    try:
        password = ""
        tmp_pass = options2passwd(options)
        if tmp_pass:
            password = tmp_pass

        unpacked = unpack(filepath=filename, password=password)
        if unpacked.children:
            options = Config()
            tmp_path = options.cuckoo.get("tmppath", "/tmp")
            target_path = os.path.join(tmp_path, "cuckoo-sflock")
            if not os.path.exists(target_path):
                os.mkdir(target_path)
            tmp_dir = tempfile.mkdtemp(dir=target_path)

            retlist = get_filenames([], tmp_dir, unpacked.children)

            if retlist:
                unpacked.extract(tmp_dir)

    except Exception as err:
        log.error("Error unpacking file: {} - {}".format(filename, err))

    return retlist


def demux_sample(filename, package, options):
    # if a package was specified, then don't do anything special
    if package:
        return [filename]

    # don't try to extract from office docs
    magic = File(filename).get_type()

    # if file is an Office doc and password is supplied, try to decrypt the doc
    if "Microsoft" in magic:
        if "Outlook" in magic or "Message" in magic:
            log.debug("Extracting msg file - {}".format(filename))
            pass
        elif "Composite Document File" in magic or "CDFV2 Encrypted" in magic:
            password = False
            tmp_pass = options2passwd(options)
            if tmp_pass:
                password = tmp_pass
            if password:
                log.debug("Extracting from Office doc - {}, password={}".format(filename, password))
                return demux_office(filename, password)
            else:
                log.debug("Submitting Office document - {}".format(filename))
                return [filename]
        else:
            return [filename]

    # don't try to extract from Java archives or executables
    if "Java Jar" in magic:
        return [filename]
    if "PE32" in magic or "MS-DOS executable" in magic:
        return [filename]

    retlist = list()
    if HAS_SFLOCK:
        # all in one unarchiver
        retlist = demux_sflock(filename, options)

    # if it wasn't a ZIP or an email or we weren't able to obtain anything interesting from either, then just submit the
    # original file
    if not retlist:
        retlist.append(filename)
        log.warn("Not an archive file or does not contain valid files- {}".format(filename))
    else:
        if len(retlist) > 10:
            retlist = retlist[:10]

    return retlist
