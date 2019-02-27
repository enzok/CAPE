from django.conf.urls import url
from guacamole import views

urlpatterns = [
    url(r'^(?P<task_id>\d+)/$', views.index, name='guacamole'),
    url(r"^\d+/tunnel/(?P<host>[\w-]+)/command$", views.tunnel, name='tunnel'),
]
