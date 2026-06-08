# topology/urls.py
from django.urls import path
from . import views

app_name = 'topology'

urlpatterns = [
    path('', views.topology_dashboard_view, name='topology_dashboard'),
    path('topology/network-graph-json/', views.topology_network_graph_json, name='topology_network_graph_json'),
    path('topology/api/reachability/<int:host_id>/', views.host_reachability_matrix, name='host_reachability'),
    path('api/scan-info/<int:device_id>/', views.get_scan_info, name='get_scan_info'),
    path('topology/', views.topology_dashboard_view, name='topology_dashboard_view'),

]