# hosts/urls.py
from django.urls import path
from . import views

app_name = 'hosts'

urlpatterns = [
    path('', views.hosts_dashboard_view, name='index'),
]