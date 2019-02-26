# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import threading
import uuid
from time import sleep

from django.conf import settings
from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.guacamole.client import GuacamoleClient

logger = logging.getLogger(__name__)
sockets = {}
sockets_lock = threading.RLock()
read_lock = threading.RLock()
write_lock = threading.RLock()
pending_read_request = threading.Event()


def index(request, task_id):
    sleep(5)
    db = Database()
    task = db.view_task(task_id)
    machine = db.view_machine(task.machine)
    if not task or not machine:
        return render(request, "error.html", {"error": "Task or machine does not exist."})
    if task.status == "running":
        return render(request, "guacamole/index.html", {"hostname": task.machine,
                                                        "host_ip": machine.ip})
    elif task.status == "pending":
        return render(request, "guacamole/status.html", {"task_id": task_id})
    elif task.status == "failed" or task.status == "completed" or task.status == "reported":
        return render(request, "error.html",
                      {"error": "Task not available for remote control. It may have already completed."})


@csrf_exempt
def tunnel(request, host):
    qs = request.META['QUERY_STRING']
    logger.info('tunnel %s', qs)
    if qs == 'connect':
        return _do_connect(request, host)
    else:
        tokens = qs.split(':')
        if len(tokens) >= 2:
            if tokens[0] == 'read':
                return _do_read(request, tokens[1])
            elif tokens[0] == 'write':
                return _do_write(request, tokens[1])

    return HttpResponse(status=400)


def _do_connect(request, host):
    # Connect to guacd daemon
    client = GuacamoleClient(settings.GUACD_HOST, int(settings.GUACD_PORT))
    client.handshake(protocol=settings.GUAC_PROTO,
                     hostname=host,
                     port=int(settings.GUAC_PORT),
                     username=settings.GUAC_USER,
                     password=settings.GUAC_PASS)

    cache_key = str(uuid.uuid4())
    with sockets_lock:
        logger.info('Saving socket with key %s', cache_key)
        sockets[cache_key] = client

    response = HttpResponse(content=cache_key)
    response['Cache-Control'] = 'no-cache'

    return response


def _do_read(request, cache_key):
    pending_read_request.set()

    def content():
        with sockets_lock:
            client = sockets[cache_key]

        with read_lock:
            pending_read_request.clear()

            while True:
                # instruction = '5.mouse,3.400,3.500;'
                instruction = client.receive()
                if instruction:
                    yield instruction
                else:
                    break

                if pending_read_request.is_set():
                    logger.info('Letting another request take over.')
                    break

            # End-of-instruction marker
            yield '0.;'

    response = StreamingHttpResponse(content(), content_type='application/octet-stream')
    response['Cache-Control'] = 'no-cache'
    return response


def _do_write(request, cache_key):
    with sockets_lock:
        client = sockets[cache_key]

    with write_lock:
        while True:
            chunk = request.read(8192)
            if chunk:
                client.send(chunk)
            else:
                break

    response = HttpResponse(content_type='application/octet-stream')
    response['Cache-Control'] = 'no-cache'
    return response
