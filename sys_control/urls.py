from django.urls import path
from .views import sys_control_view

app_name = 'sys_control'  # Enables namespacing (e.g., 'networks:matrix')

urlpatterns = [
    # URL for the matrix visualization 
    # Example: /networks/5/matrix/

    path('controlpanel/', sys_control_view, name='control_dashboard'),

]