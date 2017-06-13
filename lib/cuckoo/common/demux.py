# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import tempfile
import gzip
import tarfile
import logging
from bz2 import BZ2File
from zipfile import ZipFile
from sflock import unpack

try:
    from rarfile import RarFile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.email_utils import find_attachments_in_email
from lib.cuckoo.common.office.msgextract import Message
from lib.cuckoo.common.exceptions import CuckooDemuxError

log = logging.getLogger(__name__)

demux_extensions_list = [
        "", ".exe", ".dll", ".com", ".jar", ".pdf", ".msi", ".bin", ".scr", ".zip", ".tar", ".gz", ".tgz", ".rar", ".htm", ".html", ".hta",
        ".doc", ".dot", ".docx", ".dotx", ".docm", ".dotm", ".docb", ".mht", ".mso", ".js", ".jse", ".vbs", ".vbe",
        ".xls", ".xlt", ".xlm", ".xlsx", ".xltx", ".xlsm", ".xltm", ".xlsb", ".xla", ".xlam", ".xll", ".xlw",
        ".ppt", ".pot", ".pps", ".pptx", ".pptm", ".potx", ".potm", ".ppam", ".ppsx", ".ppsm", ".sldx", ".sldm", ".wsf",
    ]

archive_extensions_list = [
        "", ".bin", ".zip", ".tar", ".gz", ".tgz", ".rar", ".ace", ".bup", ".eml", ".msg", ".mso",
    ]

def demux_office(filename, password):
    retlist = []

    options = Config()
    aux_options = Config("auxiliary")
    tmp_path = options.cuckoo.get("tmppath", "/tmp")
    decryptor = aux_options.msoffice.get("decryptor", None)
    result = 0

    if decryptor and os.path.exists(decryptor):
        basename = os.path.basename(filename)
        target_path = os.path.join(tmp_path, "msoffice-crypt-tmp")
        if not os.path.exists(target_path):
            os.mkdir(target_path)
        decrypted_name = os.path.join(target_path, basename)

        try:
            result = subprocess.call([decryptor, "-p", password, "-d", filename, decrypted_name])
        except:
            pass

        if result == 0 or result == 2:
            retlist.append(decrypted_name)
        elif result == 1:
            raise CuckooDemuxError("MS Office decryptor: unsupported document type")
        elif result == 3:
            raise CuckooDemuxError("MS Office decryptor: bad password")
    else:
        raise CuckooDemuxError("MS Office decryptor binary not found")

    if not retlist:
        retlist.append(filename)

    return retlist


def demux_zip(filename, options):
    retlist = []

    try:
        # only extract from files with no extension or with .bin (downloaded from us) or .zip extensions
        ext = os.path.splitext(filename)[1]
        if ext != "" and ext != ".zip" and ext != ".bin":
            return retlist

        extracted = []
        password="infected"
        fields = options.split(",")
        for field in fields:
            try:
                key, value = field.split("=", 1)
                if key == "password":
                    password = value
                    break
            except:
                pass

        with ZipFile(filename, "r") as archive:
            infolist = archive.infolist()
            for info in infolist:
                # avoid obvious bombs
                if info.file_size > 100 * 1024 * 1024 or not info.file_size:
                    continue
                # ignore empty filenames
                if not info.filename:
                    continue
                # ignore directories
                if info.filename.endswith("/"):
                    continue
                base, ext = os.path.splitext(info.filename)
                basename = os.path.basename(info.filename)
                ext = ext.lower()
                if ext == "" and len(basename) and basename[0] == ".":
                    continue
                for theext in demux_extensions_list:
                    if ext == theext:
                        extracted.append(info.filename)
                        break

            if extracted:
                options = Config()
                tmp_path = options.cuckoo.get("tmppath", "/tmp")
                target_path = os.path.join(tmp_path, "cuckoo-zip-tmp")
                if not os.path.exists(target_path):
                    os.mkdir(target_path)
                tmp_dir = tempfile.mkdtemp(prefix='cuckoozip_',dir=target_path)

                for extfile in extracted:
                    try:
                        retlist.append(archive.extract(extfile, path=tmp_dir, pwd=password))
                    except:
                        retlist.append(archive.extract(extfile, path=tmp_dir))
                    print ("Extracting from zip - {}/{}".format(tmp_dir, extfile))
    except:
        pass

    return retlist

def demux_rar(filename, options):
    retlist = []

    if not HAS_RARFILE:
        return retlist

    try:
        extracted = []
        password="infected"
        fields = options.split(",")
        for field in fields:
            try:
                key, value = field.split("=", 1)
                if key == "password":
                    password = value
                    break
            except:
                pass

        with RarFile(filename, "r") as archive:
            infolist = archive.infolist()
            for info in infolist:
                # avoid obvious bombs
                if info.file_size > 100 * 1024 * 1024 or not info.file_size:
                    continue
                # ignore empty filenames
                if not info.filename:
                    continue
                # ignore directories
                if info.filename.endswith("\\"):
                    continue
                # add some more sanity checking since RarFile invokes an external handler
                if "..\\" in info.filename:
                    continue
                base, ext = os.path.splitext(info.filename)
                basename = os.path.basename(info.filename)
                ext = ext.lower()
                if ext == "" and len(basename) and basename[0] == ".":
                    continue
                for theext in demux_extensions_list:
                    if ext == theext:
                        extracted.append(info.filename)
                        break

            if extracted:
                options = Config()
                tmp_path = options.cuckoo.get("tmppath", "/tmp")
                target_path = os.path.join(tmp_path, "cuckoo-rar-tmp")
                if not os.path.exists(target_path):
                    os.mkdir(target_path)
                tmp_dir = tempfile.mkdtemp(prefix='cuckoorar_',dir=target_path)

                for extfile in extracted:
                    # RarFile differs from ZipFile in that extract() doesn't return the path of the extracted file
                    # so we have to make it up ourselves
                    try:
                        archive.extract(extfile, path=tmp_dir, pwd=password)
                        retlist.append(os.path.join(tmp_dir, extfile.replace("\\", "/")))
                    except:
                        archive.extract(extfile, path=tmp_dir)
                        retlist.append(os.path.join(tmp_dir, extfile.replace("\\", "/")))
    except:
        pass

    return retlist

def demux_tar(filename, options):
    retlist = []
    ext = ""

    try:
        # only extract from files with no extension or with .bin (downloaded from us) or .tar/tarball extensions
        ext = os.path.splitext(filename)[1]
        if ext != "" and ext != ".tar" and ext != ".gz" and ext != ".tgz" and ext != ".bz2" and ext != ".tbz2" and ext != ".bin":
            return retlist

        extracted = []

        with tarfile.open(filename, "r") as archive:
            infolist = archive.getmembers()
            for info in infolist:
                # avoid obvious bombs
                if info.size > 100 * 1024 * 1024 or not info.size:
                    continue
                # ignore non-regular files
                if not info.isreg():
                    continue
                base, ext = os.path.splitext(info.name)
                basename = os.path.basename(info.name)
                ext = ext.lower()
                if ext == "" and len(basename) and basename[0] == ".":
                    continue
                for theext in demux_extensions_list:
                    if ext == theext:
                        extracted.append(info)
                        break

            if extracted:
                options = Config()
                tmp_path = options.cuckoo.get("tmppath", "/tmp")
                target_path = os.path.join(tmp_path, "cuckoo-tar-tmp")
                if not os.path.exists(target_path):
                    os.mkdir(target_path)
                tmp_dir = tempfile.mkdtemp(prefix='cuckootar_',dir=target_path)

                for extfile in extracted:
                    fobj = archive.extractfile(extfile)
                    outpath = os.path.join(tmp_dir, extfile.name)
                    outfile = open(outpath, "wb")
                    outfile.write(fobj.read())
                    fobj.close()
                    outfile.close()
                    retlist.append(outpath)
    except:
        if ext == ".tgz" or ext == ".tbz2" or ext == ".tar":
            return retlist
        # handle gzip
        try:
            gzfinal = os.path.basename(os.path.splitext(filename)[0])
            with gzip.open(filename, "rb") as fobj:
                options = Config()
                tmp_path = options.cuckoo.get("tmppath", "/tmp")
                target_path = os.path.join(tmp_path, "cuckoo-tar-tmp")
                if not os.path.exists(target_path):
                    os.mkdir(target_path)
                tmp_dir = tempfile.mkdtemp(prefix='cuckootar_',dir=target_path)
                outpath = os.path.join(tmp_dir, gzfinal)
                outfile = open(outpath, "wb")
                outfile.write(fobj.read())
                outfile.close()
            retlist.append(outpath)
        except:
            pass

        # handle bzip2
        try:
            gzfinal = os.path.basename(os.path.splitext(filename)[0])
            with BZ2File(filename, "rb") as fobj:
                options = Config()
                tmp_path = options.cuckoo.get("tmppath", "/tmp")
                target_path = os.path.join(tmp_path, "cuckoo-tar-tmp")
                if not os.path.exists(target_path):
                    os.mkdir(target_path)
                tmp_dir = tempfile.mkdtemp(prefix='cuckootar_',dir=target_path)
                outpath = os.path.join(tmp_dir, gzfinal)
                outfile = open(outpath, "wb")
                outfile.write(fobj.read())
                outfile.close()
            retlist.append(outpath)
        except:
            pass

    return retlist

def demux_email(filename, options):
    retlist = []
    try:
        with open(filename, "rb") as openfile:
            buf = openfile.read()
            atts = find_attachments_in_email(buf, True)
            if atts and len(atts):
                for att in atts:
                    retlist.append(att[0])
    except:
        pass

    return retlist

def demux_msg(filename, options):
    retlist = []
    try:
        retlist = Message(filename).get_extracted_attachments()
    except:
        pass

    return retlist

def get_filenames(retlist, tmp_dir, children):
    for child in children:
        at = child.astree()
        if 'file' in at['type']:
            retlist.append(os.path.join(tmp_dir, at['filename']))
        elif 'container' in at['type']:
            if not at['package'] in ('doc','xls','ppt'):
                print "{} is a container".format(at['filename'])
                get_filenames(retlist, tmp_dir, child.children)
            else:
                print "Archive {} contains an MS Office file {}".format(filename, at['filename'])
                retlist.append(os.path.join(tmp_dir, at['filename']))

    return retlist

def demux_all(filename, options):
    retlist = []
    try:
        # only extract from files with desired archive extensions
        ext = os.path.splitext(filename)[1]
        if ext not in archive_extensions_list:
            return retlist

        password = "infected"
        fields = options.split(",")
        for field in fields:
            try:
                key, value = field.split("=", 1)
                if key == "password":
                    password = value
                    break
            except:
                pass

            options = Config()
            tmp_path = options.cuckoo.get("tmppath", "/tmp")
            target_path = os.path.join(tmp_path, "cuckoo-zip-tmp")
            if not os.path.exists(target_path):
                os.mkdir(target_path)
            
            tmp_dir = tempfile.mkdtemp(prefix='cuckoozip_', dir=target_path)
            unpacked = unpack(filepath=filename, password=password)
            retlist = get_filenames([], tmp_dir, unpacked.children)
            if retlist:
                unpacked.extract(tmp_dir)
                print ("Extracted from file - {}->{}".format(filename, retlist))

    except Exception as err:
        print ("Error unpacking file: {} - {}".format(filename, err))
        pass

    return retlist


def demux_sample(filename, package, options):
    """
    If file is a ZIP, extract its included files and return their file paths
    If file is an email, extracts its attachments and return their file paths (later we'll also extract URLs)
    If file is a password-protected Office doc and password is supplied, return path to decrypted doc
    """

    magic = File(filename).get_type()

    # if file is an Office doc and password is supplied, try to decrypt the doc
    if "Microsoft" in magic or "Composite Document File" in magic or "CDFV2 Encrypted" in magic:
        password = None
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
        if password:
            return demux_office(filename, password)
            print ("Extracting from Office doc - {}, password={}".format(filename, password))
        else:
            return [filename]
            print ("Extracting from Office doc - {}".format(filename))

    # if a package was specified, then don't do anything special
    # this will allow for the ZIP package to be used to analyze binaries with included DLL dependencies
    # do the same if file= is specified in the options
    if package or "file=" in options:
        return [ filename ]

    # don't try to extract from Java archives or executables
    if "Java Jar" in magic or "Java archive" in magic:
        return [ filename ]
    if "PE32" in magic or "MS-DOS executable" in magic:
        return [ filename ]

    #add .ace extension to ACE files or unace will fail
    if "ACE" in magic or "ACE archive" in magic:
        if not filename.endswith(".ace"):
            os.rename(filename, filename + ".ace")
            filename += ".ace"

    retlist = demux_all(filename, options)

    # if it wasn't a ZIP or an email or we weren't able to obtain anything interesting from either, then just submit the
    # original file

    if not retlist:
        retlist.append(filename)
        print ("Not an archive file - {}".format(filename))

    return retlist
