# topology/urls.py
from django.urls import path
from . import views

app_name = 'topology'

urlpatterns = [
    path('', views.topology_dashboard_view, name='topology_dashboard'),
    path('network-graph-json/', views.topology_network_graph_json, name='topology_network_graph_json'),
    path('api/reachability/<int:host_id>/', views.host_reachability_matrix, name='host_reachability'),
]