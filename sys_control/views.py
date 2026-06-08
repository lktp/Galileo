from django.shortcuts import render, redirect
from django.contrib import messages
from characterization.models import ArpEntry
from hosts.models import Host
from topology.models import PortAttachment
from .utils import reconcile_network_topology # Your reconciliation function

def sys_control_view(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'clear_all':
            # Clear tables (order matters to avoid foreign key errors)
            PortAttachment.objects.all().delete()
            ArpEntry.objects.all().delete()
            Host.objects.all().delete()
            messages.success(request, "All network data has been cleared.")
            
        elif action == 'run_reconciliation':
            reconcile_network_topology()
            messages.success(request, "Topology reconciliation complete.")
            
        return redirect('sys_control:control_dashboard')

    return render(request, 'sys_control/dashboard.html')