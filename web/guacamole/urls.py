from django.conf.urls import url
from guacamole import views

urlpatterns = [
    url(r'^(?P<task_id>\d+)/$', views.index, name='guacamole'),
    url(r"^(?P<task_id>\d+)/tunnel/(?P<host>\w+)/.*$", views.tunnel, name='tunnel'),
]
