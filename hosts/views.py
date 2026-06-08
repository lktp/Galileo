
from django.shortcuts import render, redirect,  get_object_or_404
from .models import Host
from .utils import parse_nmap_xml
from characterization.models import Network # Import Network to pull options list
from django.db.models import Q
from django.db.models import Count

def hosts_dashboard_view(request):
    if request.method == 'POST':
        uploaded_file = request.FILES.get('nmap_file')
        network_id = request.POST.get('associated_network')
        
        network_obj = None
        if network_id:
            network_obj = get_object_or_404(Network, pk=network_id)

        if uploaded_file:
            uploaded_file.seek(0)
            try:
                raw_text = uploaded_file.read().decode('utf-8')
                parse_nmap_xml(raw_text, network_obj=network_obj)
            except Exception:
                pass
            
            return redirect('/hosts/')

    # --- GET LOGIC: DYNAMIC NETWORK VISIBILITY FILTERING ---
    active_filter_id = request.GET.get('network_filter')
    
    # Base query for all hosts
    host_query = Host.objects.all().prefetch_related('open_ports')
    
    # Apply filter state if an active parameter exists in the browser URL path
    if active_filter_id == 'standalone':
        host_query = host_query.filter(network__isnull=True)
    elif active_filter_id:
        host_query = host_query.filter(network_id=active_filter_id)

    #hosts = host_query.order_by('ip_address')
    hosts = Host.objects.annotate(num_ports=Count('open_ports'))
    networks = Network.objects.all().order_by('-created_at')
    
    context = {
        'hosts': hosts,
        'networks': networks,
        'active_filter_id': active_filter_id, # Pass to track the "active" CSS state on buttons
    }
    return render(request, 'hosts/dashboard.html', context)