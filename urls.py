from django.urls import path
from .views import network_matrix_view, network_dashboard_view, global_dashboard_view, signatures_dashboard_view, restore_signature, toggle_signature_active, backup_signature

app_name = 'characterization'  # Enables namespacing (e.g., 'networks:matrix')

urlpatterns = [
    # URL for the matrix visualization 
    # Example: /networks/5/matrix/
    path('network/', network_dashboard_view, name='dashboard'),
    path('signatures/', signatures_dashboard_view, name='signatures_dashboard'),

    # 2. Action Routes (These process data, then redirect back to the dashboard above)
    path('signatures/<int:sig_id>/toggle/', toggle_signature_active, name='toggle_signature'),
    path('signatures/<int:sig_id>/backup/', backup_signature, name='backup_signature'),
    
    # 3. The Restore Route (Receives the backup ID via a POST form submission)
    path('signatures/restore/', restore_signature, name='restore_signature_post'),
    path('', global_dashboard_view, name='dashboard'),

]