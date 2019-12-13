# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import shutil
import sys
import time
from lib.api.process import Process
from lib.common.abstracts import Package
from lib.common.defines import ADVAPI32, KERNEL32
import logging
import ctypes

INJECT_CREATEREMOTETHREAD = 0
INJECT_QUEUEUSERAPC = 1

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SC_MANAGER_LOCK = 0x0008
SC_MANAGER_QUERY_LOCK_STATUS = 0x0010
SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020
SC_MANAGER_ALL_ACCESS = SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS | SC_MANAGER_MODIFY_BOOT_CONFIG
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_PAUSE_CONTINUE = 0x0040
SERVICE_INTERROGATE = 0x0080
SERVICE_USER_DEFINED_CONTROL = 0x0100
SERVICE_ALL_ACCESS = SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL
SERVICE_WIN32_OWN_PROCESS = 0x0010
SERVICE_INTERACTIVE_PROCESS = 0x0100
SERVICE_DEMAND_START = 0x0003
SERVICE_ERROR_IGNORE = 0x0000
SERVICE_CONTROL_STOP = 0x00000001
SERVICE_STOPPED = 0x00000001

log = logging.getLogger(__name__)

class IISSERVICE(Package):
    """Service analysis package."""

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

            servproc = Process(options=self.options, config=self.config, pid=self.config.services_pid, suspended=False)
            filepath = servproc.get_filepath()
            servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
            servproc.close()
            KERNEL32.Sleep(2000)

            scm_handle = ADVAPI32.OpenSCManagerA(None, None, SC_MANAGER_ALL_ACCESS)
            if scm_handle == 0:
                log.info("Failed to open SCManager")
                log.info(ctypes.FormatError())
                return

            servicename = "W3svc"
            service_handle = ADVAPI32.OpenServiceA(scm_handle, servicename, SERVICE_ALL_ACCESS)
            if service_handle == 0:
                log.info("Failed to open service")
                log.info(ctypes.FormatError())
                return
            log.info("Opened service (handle: 0x%x)", service_handle)

            if service_handle:
                service_launched = ADVAPI32.StartServiceA(service_handle, 0, None)
                if service_launched:
                    log.info("Successfully started service")
                else:
                    log.info("Failed to start service")
                    return

            ADVAPI32.CloseServiceHandle(service_handle)
            ADVAPI32.CloseServiceHandle(scm_handle)
            return
        except Exception as e:
            log.info(sys.exc_info()[0])
            log.info(e)
            log.info(e.__dict__)
            log.info(e.__class__)
            log.exception(e)
