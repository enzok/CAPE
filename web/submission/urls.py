# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import url
from submission import views
from guacamole import views as guac_views

urlpatterns = [
    url(r"^$", views.index, name='submission'),
    url(r"^resubmit/(?P<resubmit_hash>[\w\d]{64})/$", views.index, name='submission'),
    url(r"status/(?P<task_id>\d+)/$", views.status, name='submission_status'),
    url(r"status/(?P<task_id>\d+)/$", guac_views.index, name='guacamole'),
]
