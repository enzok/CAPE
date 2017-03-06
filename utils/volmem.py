# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import argparse
from pprint import pprint

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.demux import demux_all
from lib.cuckoo.common.constants import CUCKOO_ROOT
from modules.processing.memory import VolatilityManager, VolatilityAPI
from lib.cuckoo.core.startup import ConsoleHandler


class Memory(VolatilityManager):

    def run(self):
        results = {}

        # Exit if options were not loaded.
        if not self.voptions:
            return

        vol = VolatilityAPI(self.memfile, self.osprofile)

        # TODO: improve the load of volatility functions.
        if self.voptions.pslist.enabled:
            results["pslist"] = vol.pslist()
        if self.voptions.psxview.enabled:
            results["psxview"] = vol.psxview()
        if self.voptions.callbacks.enabled:
            results["callbacks"] = vol.callbacks()
        if self.voptions.idt.enabled:
            try:
                results["idt"] = vol.idt()
            except:
                pass
        if self.voptions.ssdt.enabled:
            results["ssdt"] = vol.ssdt()
        if self.voptions.gdt.enabled:
            try:
                results["gdt"] = vol.gdt()
            except:
                pass
        if self.voptions.timers.enabled:
            results["timers"] = vol.timers()
        if self.voptions.messagehooks.enabled:
            results["messagehooks"] = vol.messagehooks()
        if self.voptions.getsids.enabled:
            results["getsids"] = vol.getsids()
        if self.voptions.privs.enabled:
            results["privs"] = vol.privs()
        if self.voptions.malfind.enabled:
            results["malfind"] = vol.malfind()
        if self.voptions.apihooks.enabled:
            results["apihooks"] = vol.apihooks()
        if self.voptions.dlllist.enabled:
            results["dlllist"] = vol.dlllist()
        if self.voptions.handles.enabled:
            results["handles"] = vol.handles()
        if self.voptions.ldrmodules.enabled:
            results["ldrmodules"] = vol.ldrmodules()
        if self.voptions.mutantscan.enabled:
            results["mutantscan"] = vol.mutantscan()
        if self.voptions.devicetree.enabled:
            results["devicetree"] = vol.devicetree()
        if self.voptions.svcscan.enabled:
            results["svcscan"] = vol.svcscan()
        if self.voptions.modscan.enabled:
            results["modscan"] = vol.modscan()
        if self.voptions.yarascan.enabled:
            results["yarascan"] = vol.yarascan()
        if self.voptions.sockscan.enabled and self.osprofile.lower().startswith("winxp"):
            results["sockscan"] = vol.sockscan()
        if self.voptions.netscan.enabled and (
                self.osprofile.lower().startswith("win7") or self.osprofile.lower().startswith("vista")):
            results["netscan"] = vol.netscan()

        self.find_taint(results)
        self.do_strings()
        self.cleanup()

        return self.mask_filter(results)


def analyze(task, mem_profile):
        """Run analysis.
        @return: volatility results dict.
        """
        memory_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task, "memory.dmp.zip")
        results = {}
        options = ""

        if memory_path and os.path.exists(memory_path):
            try:
                print "Retrieving and unzipping memory file {}".format(memory_path)
                memory_file = demux_all(memory_path, options)
                if memory_file:
                    try:
                        vol = Memory(memory_file[0], mem_profile)
                        vol.voptions = Config("memory")
                        vol.voptions.basic.delete_memdump = True
                        results = vol.run()
                    except Exception:
                        log.exception("Generic error executing volatility")
            except Exception as e:
                log.exception("Error unzipping memory dump file: %s", e)

        else:
            log.error("Memory dump not found: to run volatility you have to enable memory_dump")

        return results


def init_logging(auto=False, tid=0, debug=False):
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    if auto:
        fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "process.log"))
    else:
        fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "process-%s.log" % tid))

    fh.setFormatter(formatter)
    log.addHandler(fh)

    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    logging.getLogger("urllib3").setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task", type=str, help="ID of task to analyze.")
    parser.add_argument("mem_profile", type=str, help="memory profile")
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    args = parser.parse_args()

    init_logging(tid=args.task, debug=args.debug)
    results = analyze(task=args.task, mem_profile=args.mem_profile)
    pprint(results)

if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
