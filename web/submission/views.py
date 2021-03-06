# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

import requests
import tempfile
import random

try:
    import re2 as re
except ImportError:
    import re

from django.conf import settings
from django.shortcuts import redirect, render
from django.contrib.auth.decorators import login_required

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import store_temp_file, validate_referrer, sanitize_filename, \
    get_user_filename, generate_fake_name
from lib.cuckoo.common.quarantine import unquarantine
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.core.database import Database
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.web_utils import get_magic_type, download_file, get_file_content, _download_file


# this required for hash searches
FULL_DB = False

aux_conf = Config("auxiliary")
repconf = Config("reporting")
cfg = Config("cuckoo")
processing_cfg = Config("processing")

if repconf.mongodb.enabled:
    import pymongo
    results_db = pymongo.MongoClient(repconf.mongodb.host,
                                     port=repconf.mongodb.port,
                                     username=repconf.mongodb.get("username", None),
                                     password=repconf.mongodb.get("password", None),
                                     authSource=repconf.mongodb.db
                                     )[repconf.mongodb.db]
    FULL_DB = True

# Conditional decorator for web authentication
class conditional_login_required(object):
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition
    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)

def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value

def update_options(gw, orig_options):
    options = orig_options
    if gw:
        if orig_options:
            options = orig_options + ",setgw=%s" % (gw)
        else:
            options = "setgw=%s" % (gw)
        if settings.GATEWAYS_IP_MAP.has_key(gw) and settings.GATEWAYS_IP_MAP[gw]:
            options += ",gwname=%s" % (settings.GATEWAYS_IP_MAP[gw])

    return options

def load_vms_tags():
    all_tags = list()
    for machine in Database().list_machines():
        for tag in machine.tags:
            all_tags.append(tag.name)

    return all_tags


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request, resubmit_hash=False):
    submitter = []
    if request.META['HTTP_X_REMOTE_USER']:
        submitter = request.META['HTTP_X_REMOTE_USER']
    if request.method == "POST":
        package = request.POST.get("package", "")
        timeout = min(force_int(request.POST.get("timeout")), 60 * 60 * 24)
        options = request.POST.get("options", "")
        priority = force_int(request.POST.get("priority"))
        machine = request.POST.get("machine", "")
        gateway = request.POST.get("gateway", None)
        clock = request.POST.get("clock", None)
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))
        referrer = validate_referrer(request.POST.get("referrer", None))
        tags = request.POST.get("tags", None)
        static = bool(request.POST.get("static", False))
        opt_filename = ""
        for option in options.split(","):
            if option.startswith("filename="):
                opt_filename = option.split("filename=")[1].encode('utf8', 'replace')
                break
        task_gateways = []
        ipaddy_re = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

        if referrer:
            if options:
                options += ","
            options += "referrer=%s" % (referrer)

        if request.POST.get("free"):
            if options:
                options += ","
            options += "free=yes"

        if request.POST.get("nohuman"):
            if options:
                options += ","
            options += "nohuman=yes"

        if request.POST.get("tor"):
            if options:
                options += ","
            options += "tor=yes"

        if request.POST.get("process_dump"):
            if options:
                options += ","
            options += "procdump=0"
        else:
            if options:
                options += ","
            options += "procdump=1"

        if request.POST.get("process_memory"):
            if options:
                options += ","
            options += "procmemdump=1"

        if request.POST.get("import_reconstruction"):
            if options:
                options += ","
            options += "import_reconstruction=1"

        if request.POST.get("disable_cape"):
            if options:
                options += ","
            options += "disable_cape=1"

        if request.POST.get("cuckoomon_dll"):
            if options:
                options += ","
            options += "dll=cuckoomon.dll"

        if request.POST.get("scriptdump_dll"):
            if options:
                options += ","
            options += "dll=ScriptDump.dll"

        if request.POST.get("kernel_analysis"):
            if options:
                options += ","
            options += "kernel_analysis=yes"

        if request.POST.get("norefer"):
            if options:
                options += ","
            options += "norefer=1"

        if request.POST.get("save_memory"):
            if options:
                options += ","
            options += "save_memory=yes"

        if request.POST.get("posproc"):
            if options:
                options += ","
            options += "posproc=1"

        if submitter:
            if options:
                options += ","
            options += "submitter={}".format(submitter)

        if request.POST.get("oldloader"):
            if options:
                options += ","
            options += "loader=oldloader.exe,loader_64=oldloader_x64.exe"

        if request.POST.get("addpassword"):
            if options:
                options += ","
            options += "password={}".format(settings.ZIP_PWD)

        orig_options = options

        if gateway and gateway.lower() == "all":
            for e in settings.GATEWAYS:
                if ipaddy_re.match(settings.GATEWAYS[e]):
                    task_gateways.append(settings.GATEWAYS[e])
        elif gateway and gateway in settings.GATEWAYS:
            if "," in settings.GATEWAYS[gateway]:
                if request.POST.get("all_gw_in_group"):
                    tgateway = settings.GATEWAYS[gateway].split(",")
                    for e in tgateway:
                        task_gateways.append(settings.GATEWAYS[e])
                else:
                    tgateway = random.choice(settings.GATEWAYS[gateway].split(","))
                    task_gateways.append(settings.GATEWAYS[tgateway])
            else:
                task_gateways.append(settings.GATEWAYS[gateway])

        if not task_gateways:
            # To reduce to the default case
            task_gateways = [None]

        db = Database()
        task_ids = []
        task_machines = []

        if machine.lower() == "all":
            for entry in db.list_machines():
                task_machines.append(entry.label)
        else:
            task_machines.append(machine)

        failed_hashes = list()
        status = "ok"
        if "hash" in request.POST and request.POST.get("hash", False) and request.POST.get("hash")[0] != '':
            resubmission_hash = request.POST.get("hash").strip()
            tmp_paths = db.sample_path_by_hash(resubmission_hash)
            storage_path = os.path.join(settings.CUCKOO_PATH, "storage", "binaries", resubmission_hash)
            if tmp_paths:
                content = get_file_content(tmp_paths)
                if not content:
                    content = get_file_content(storage_path)

                    if not content:
                        return render(request, "error.html",
                                      {"error": "Can't find {} on disk".format(resubmission_hash)})

                if opt_filename:
                    filename = opt_filename
                else:
                    filename = resubmission_hash

                path = store_temp_file(content, filename)
                headers = {}
                url = 'local'
                params = {}

                status, task_ids = download_file(False, content, request, db, task_ids, url, params, headers, "Local",
                                                 path, package, timeout, options, priority, machine, clock,
                                                 custom, memory, enforce_timeout, referrer, tags, orig_options,
                                                 task_gateways, task_machines, static)

                if status != "ok":
                    failed_hashes.append(h)

        elif "sample" in request.FILES:
            samples = request.FILES.getlist("sample")
            for sample in samples:
                # Error if there was only one submitted sample and it's empty.
                # But if there are multiple and one was empty, just ignore it.
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {"error": "You uploaded an empty file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html",
                                  {"error": "Uploaded file exceeds maximum size specified in "
                                            "web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                if opt_filename:
                    filename = opt_filename
                else:
                    filename = sample.name
                path = store_temp_file(sample.read(), filename)

                for gw in task_gateways:
                    options = update_options(gw, orig_options)

                    for entry in task_machines:
                        try:
                            task_ids_new = db.demux_sample_and_add_to_db(file_path=path,
                                                                         package=package,
                                                                         timeout=timeout,
                                                                         options=options,
                                                                         priority=priority,
                                                                         machine=entry,
                                                                         custom=custom,
                                                                         memory=memory,
                                                                         enforce_timeout=enforce_timeout,
                                                                         tags=tags,
                                                                         clock=clock,
                                                                         static=static)
                            task_ids.extend(task_ids_new)
                        except CuckooDemuxError as err:
                            return render(request, "error.html", {"error": err})

        elif "static" in request.FILES:
            samples = request.FILES.getlist("static")
            for sample in samples:
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {"error": "You uploaded an empty file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html", {"error": "You uploaded a file that exceeds the maximum allowed upload size specified in web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(), sample.name)

                task_id = db.add_static(file_path=path, priority=priority)
                if not task_id:
                    return render(request, "error.html", {"error": "We don't have static extractor for this"})
                task_ids.append(task_id)

        elif "quarantine" in request.FILES:
            samples = request.FILES.getlist("quarantine")
            for sample in samples:
                # Error if there was only one submitted sample and it's empty.
                # But if there are multiple and one was empty, just ignore it.
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html",
                                              {"error": "You uploaded an empty quarantine file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html",
                                              {"error": "Uploaded quarantine file exceeds maximum size specified " 
                                                        "in web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                tmp_path = store_temp_file(sample.read(),
                                       sample.name)

                path = unquarantine(tmp_path)
                try:
                    os.remove(tmp_path)
                except:
                    pass

                if not path:
                    return render(request, "error.html", {"error": "You uploaded an unsupported quarantine file."})

                try:
                    File(path).get_type()
                except TypeError:
                    return render(request, "error.html", {"error": "Error submitting file - bad file type"})

                for gw in task_gateways:
                    options = update_options(gw, orig_options)

                    for entry in task_machines:
                        task_ids_new = db.demux_sample_and_add_to_db(file_path=path,
                                                                     package=package,
                                                                     timeout=timeout,
                                                                     options=options,
                                                                     priority=priority,
                                                                     machine=entry,
                                                                     custom=custom,
                                                                     memory=memory,
                                                                     enforce_timeout=enforce_timeout,
                                                                     tags=tags,
                                                                     clock=clock,
                                                                     static=static)
                        task_ids.extend(task_ids_new)
        elif "pcap" in request.FILES:
            samples = request.FILES.getlist("pcap")
            for sample in samples:
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html",
                                              {"error": "You uploaded an empty PCAP file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html",
                                              {"error": "Uploaded PCAP file exceeds maximum size specified in "
                                               "web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(),
                                       sample.name)

                if sample.name.lower().endswith(".saz"):
                    saz = saz_to_pcap(path)
                    if saz:
                        try:
                            os.remove(path)
                        except:
                            pass
                        path = saz
                    else:
                        return render(request, "error.html",
                                                  {"error": "Conversion from SAZ to PCAP failed."})

                task_id = db.add_pcap(file_path=path, priority=priority)
                task_ids.append(task_id)

        elif "url" in request.POST and request.POST.get("url").strip():
            url = request.POST.get("url").strip()
            if not url:
                return render(request, "error.html",
                                          {"error": "You specified an invalid URL!"})

            url = url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
            for gw in task_gateways:
                options = update_options(gw, orig_options)

                for entry in task_machines:
                    task_id = db.add_url(url=url,
                                         package=package,
                                         timeout=timeout,
                                         options=options,
                                         priority=priority,
                                         machine=entry,
                                         custom=custom,
                                         memory=memory,
                                         enforce_timeout=enforce_timeout,
                                         tags=tags,
                                         clock=clock)
                    if task_id:
                        task_ids.append(task_id)
        elif "dlnexec" in request.POST and request.POST.get("dlnexec").strip():
            url = request.POST.get("dlnexec").strip()
            if not url:
                return render(request, "error.html",
                              {"error": "You specified an invalid URL!"})

            url = url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
            response = _download_file(request.POST.get("route", None), url, options)
            if not response:
                 return render(request, "error.html",
                               {"error": "Was impossible to retrieve url"})

            name = os.path.basename(url)
            if not "." in name:
                name = get_user_filename(options, custom) or generate_fake_name()
            path = store_temp_file(response, name)

            for entry in task_machines:
                task_id = db.demux_sample_and_add_to_db(file_path=path,
                                                        package=package,
                                                        timeout=timeout,
                                                        options=options,
                                                        priority=priority,
                                                        machine=entry,
                                                        custom=custom,
                                                        memory=memory,
                                                        enforce_timeout=enforce_timeout,
                                                        tags=tags,
                                                        clock=clock)
                if task_id:
                    task_ids += task_id
        elif settings.VTDL_ENABLED and "vtdl" in request.POST and request.POST.get("vtdl", False) \
                and request.POST.get("vtdl")[0] != '':
            vtdl = request.POST.get("vtdl").strip()
            if (not settings.VTDL_PRIV_KEY and not settings.VTDL_INTEL_KEY) or not settings.VTDL_PATH:
                    return render(request, "error.html",
                                  {"error": "VirusTotal submission requires a VTDL_PRIV_KEY or VTDL_INTEL_KEY "
                                   "variable and VTDL_PATH base directory"})
            else:
                base_dir = tempfile.mkdtemp(prefix='cuckoovtdl', dir=settings.VTDL_PATH)
                hashlist = []
                params = {}
                if "," in vtdl:
                    hashlist = vtdl.replace(" ", "").strip().split(",")
                else:
                    hashlist.append(vtdl)

                for h in hashlist:
                    if opt_filename:
                        filename = base_dir + "/" + opt_filename
                    else:
                        filename = base_dir + "/" + h

                    paths = db.sample_path_by_hash(h)
                    content = ""
                    if paths is not None:
                        content = get_file_content(paths)

                    headers = {}
                    url = "https://www.virustotal.com/api/v3/files/{id}/download".format(id=h)
                    if settings.VTDL_PRIV_KEY:
                        headers = {'x-apikey': settings.VTDL_PRIV_KEY}
                    elif settings.VTDL_INTEL_KEY:
                        headers = {'x-apikey': settings.VTDL_INTEL_KEY}

                    if not content:
                        status, task_ids = download_file(False, content, request, db, task_ids, url, params, headers,
                                                         "VirusTotal", filename, package, timeout, options, priority,
                                                         machine, clock, custom, memory, enforce_timeout, referrer,
                                                         tags, orig_options, task_gateways, task_machines, static)
                    else:
                        status, task_ids = download_file(False, content, request, db, task_ids, url, params, headers,
                                                         "Local", filename, package, timeout, options, priority,
                                                         machine, clock, custom, memory, enforce_timeout, referrer,
                                                         tags, orig_options, task_gateways, task_machines, static)
                if status != "ok":
                    failed_hashes.append(h)

        if status == "error":
            # is render msg
            return task_ids
        if isinstance(task_ids, list):
            tasks_count = len(task_ids)
        else:
            # ToDo improve error msg
            tasks_count = 0
        if tasks_count > 0:
            return render(request, "submission/complete.html",
                          {"tasks": task_ids,
                           "tasks_count": tasks_count})
        else:
            return render(request, "error.html",
                          {"error": "Error adding task to Cuckoo's database."})
    else:
        enabledconf = dict()
        enabledconf["vt"] = settings.VTDL_ENABLED
        enabledconf["kernel"] = settings.OPT_ZER0M0N
        enabledconf["zip_pwd"] = settings.ZIP_PWD
        enabledconf["posproc"] = aux_conf.posproc.get("enabled")
        enabledconf["memory"] = processing_cfg.memory.get("enabled")
        enabledconf["procmemory"] = processing_cfg.procmemory.get("enabled")
        enabledconf["tor"] = aux_conf.tor.get("enabled")
        if aux_conf.gateways:
            enabledconf["gateways"] = True
        else:
            enabledconf["gateways"] = False
        enabledconf["tags"] = False
        enabledconf["dlnexec"] = settings.DLNEXEC

        all_tags = load_vms_tags()
        if all_tags:
            enabledconf["tags"] = True

        if not enabledconf["tags"]:
            # Get enabled machinery
            machinery = cfg.cuckoo.get("machinery")
            # load multi machinery tags:
            if machinery == "multi":
                for mmachinery in Config(machinery).multi.get("machinery").split(","):
                    vms = [x.strip() for x in getattr(Config(mmachinery), mmachinery).get("machines").split(",")]
                    if any(["tags" in getattr(Config(mmachinery), vmtag).keys() for vmtag in vms]):
                        enabledconf["tags"] = True
                        break
            else:
                # Get VM names for machinery config elements
                vms = [x.strip() for x in getattr(Config(machinery), machinery).get("machines").split(",")]
                # Check each VM config element for tags
                if any(["tags" in getattr(Config(machinery), vmtag).keys() for vmtag in vms]):
                    enabledconf["tags"] = True

        files = os.listdir(os.path.join(settings.CUCKOO_PATH, "analyzer", "windows", "modules", "packages"))

        packages = []
        for name in files:
            name = os.path.splitext(name)[0]
            if name == "__init__":
                continue

            packages.append(name)

        # Prepare a list of VM names, description label based on tags.
        machines = []
        for machine in Database().list_machines():
            tags = []
            for tag in machine.tags:
                tags.append(tag.name)

            if tags:
                label = machine.label + ": " + ", ".join(tags)
            else:
                label = machine.label

            machines.append((machine.label, label))

        # Prepend ALL/ANY options.
        machines.insert(0, ("", "First available"))
        machines.insert(1, ("all", "All"))

        return render(request, "submission/index.html", {"packages": sorted(packages),
                                                         "machines": machines,
                                                         "gateways": settings.GATEWAYS,
                                                         "config": enabledconf,
                                                         "resubmit": resubmit_hash,
                                                         })

@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def status(request, task_id):
    task = Database().view_task(task_id)
    if not task:
        return render(request, "error.html",
                      {"error": "The specified task doesn't seem to exist."})

    completed = False
    if task.status == "reported":
        return redirect('report', task_id=task_id)

    status = task.status
    if status == "completed":
        status = "processing"

    return render(request, "submission/status.html",
                  {"completed": completed, "status": status, "task_id": task_id})
