# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url
from analysis import views

urlpatterns = [
    url(r"^$", views.index, name='analysis'),
    url(r"^page/(?P<page>\d+)/$", views.index, name='index'),
    url(r"^(?P<task_id>\d+)/$", views.report, name='report'),
    url(r"^surialert/(?P<task_id>\d+)/$", views.surialert, name='surialert'),
    url(r"^surihttp/(?P<task_id>\d+)/$", views.surihttp, name='surihttp'),
    url(r"^suritls/(?P<task_id>\d+)/$", views.suritls, name='suritls'),
    url(r"^surifiles/(?P<task_id>\d+)/$",views.surifiles, name='surifiles'),
    url(r"^antivirus/(?P<task_id>\d+)/$",views.antivirus, name='antivirus'),
    url(r"^shrike/(?P<task_id>\d+)/$", views.shrike, name='shrike'),
    url(r"^remove/(?P<task_id>\d+)/$", views.remove, name='remove'),
    url(r"^reschedule/(?P<task_id>\d+)/$", views.reschedule, name='reschedule'),
    url(r"^reprocess/(?P<task_id>\d+)/$", views.reprocess, name='reprocess'),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", views.chunk, name='chunk'),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/(?P<apilist>[!]?[A-Za-z_0-9,%]*)/$", views.filtered_chunk, name='filtered_chunk'),
    url(r"^search/(?P<task_id>\d+)/$", views.search_behavior, name='search_behavior'),
    url(r"^search/$", views.search, name='search'),
    url(r"^pending/$", views.pending, name='pending'),
    url(r"^procdump/(?P<task_id>\d+)/(?P<process_id>\d+)/(?P<start>\w+)/(?P<end>\w+)/$", views.procdump, name='procdump'),
    url(r"^malreport/(?P<start_date>\w+)/(?P<end_date>\w+)/$", views.malreport, name='malreport'),
    url(r"^(?P<task_id>\d+)/pcapstream/(?P<conntuple>[.,\w]+)/$", views.pcapstream, name='pcapstream'),
    url(r"^(?P<task_id>\d+)/comments/$", views.comments, name='comments'),
]
