# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import shutil
import sys
from lib.api.process import Process
from lib.common.abstracts import Package
from lib.common.defines import ADVAPI32, KERNEL32, NTDLL
from ctypes import create_string_buffer, POINTER, byref, cast, c_void_p, c_ulong
from lib.common.defines import SYSTEM_PROCESS_INFORMATION
import logging

INJECT_CREATEREMOTETHREAD = 0
INJECT_QUEUEUSERAPC = 1

log = logging.getLogger(__name__)

class IISSERVICE(Package):
    """Service analysis package."""

    def pids_from_process_name_list(self, namelist):
        proclist = []
        pidlist = []
        buf = create_string_buffer(1024 * 1024)
        p = cast(buf, c_void_p)
        retlen = c_ulong(0)
        retval = NTDLL.NtQuerySystemInformation(5, buf, 1024 * 1024, byref(retlen))
        if retval:
           return []
        proc = cast(p, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
        while proc.NextEntryOffset:
            p.value += proc.NextEntryOffset
            proc = cast(p, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
            proclist.append((proc.ImageName.Buffer[:proc.ImageName.Length/2], proc.UniqueProcessId))

        for proc in proclist:
            lowerproc = proc[0].lower()
            for name in namelist:
                if lowerproc == name:
                    pidlist.append(proc[1])
                    break
        return pidlist

    def start(self, path):
        try:
            wwwroot = self.options.get("wwwroot", "")

            # copy the webshell to specified directory
            if not wwwroot:
                wwwroot = os.path.join("inetpub", "wwwroot")
            basepath = os.getenv('SystemDrive')
            newpath = os.path.join(basepath, "\\", wwwroot, os.path.basename(path))
            log.info("newpath =  {}".format(newpath))
            shutil.copy(path, newpath)

            # get PID for w3wp.exe for monitoring services
            workerpid = self.pids_from_process_name_list(["w3wp.exe"])

            servproc = Process(options=self.options, config=self.config, pid=workerpid, suspended=False)
            filepath = servproc.get_filepath()
            servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
            servproc.close()
            KERNEL32.Sleep(1000)

            log.info("Injected into IIS worker service")
            return
        except Exception as e:
            log.info(sys.exc_info()[0])
            log.info(e)
            log.info(e.__dict__)
            log.info(e.__class__)
            log.exception(e)
