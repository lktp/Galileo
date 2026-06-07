from django.shortcuts import render
from django.http import JsonResponse
from characterization.models import DeviceConfig, Network
from .models import PortAttachment
from hosts.models import Host

def topology_dashboard_view(request):
    networks = Network.objects.all().order_by('-created_at')
    active_filter_id = request.GET.get('network_filter', '')
    
    return render(request, 'topology/map.html', {
        'networks': networks,
        'active_filter_id': active_filter_id
    })

def topology_network_graph_json(request):
    """
    API Endpoint that dynamically maps network infrastructure switches and 
    their host endpoint connections.
    """
    nodes = []
    edges = []
    seen_nodes = set()

    active_filter_id = request.GET.get('network_filter')

    # 1. FETCH PORT ATTACHMENTS FOR THE MAP
    attachments = PortAttachment.objects.all().select_related('infrastructure_device', 'connected_host')
    if active_filter_id:
        attachments = attachments.filter(infrastructure_device__network_id=active_filter_id)

    # Track which infrastructure devices are actually participating in these connections
    active_devices = set()

    # 2. PROCESS CONNECTED ENDPOINTS & EDGES
    for attach in attachments:
        if not attach.infrastructure_device:
            continue
            
        # Remember this switch ID so we can force-render it next!
        active_devices.add(attach.infrastructure_device)

        # Handle the host label and id
        if attach.connected_host:
            host_id = f"host_{attach.connected_host.id}"
            label = attach.connected_host.ip_address or f"Host-{attach.connected_host.id}"
            group_type = 'endpoint'
            title_info = f"Host: {label}<br>OS: {attach.connected_host.os_name}"
        else:
            host_id = f"mac_{attach.mac_address.replace('.', '')}"
            label = attach.mac_address
            group_type = 'endpoint'
            title_info = f"MAC: {attach.mac_address}"

        # Draw the endpoint node bubble if we haven't seen it yet
        if host_id not in seen_nodes:
            nodes.append({
                'id': host_id,
                'label': label,
                'group': group_type,
                'title': title_info
            })
            seen_nodes.add(host_id)

        # Record the connection line linking switch port to endpoint
        edges.append({
            'from': f"dev_{attach.infrastructure_device.id}",
            'to': host_id,
            'label': attach.interface_name,
            'color': {'color': '#198754'}
        })

    # 3. FORCE-RENDER THE MISSING INFRASTRUCTURE SWITCH NODES
    # This guarantees that if an edge exists, its switch parent node exists too!
    for dev in active_devices:
        node_id = f"dev_{dev.id}"
        if node_id not in seen_nodes:
            # Simple count mapping calculation for display
            attached_count = sum(1 for a in attachments if a.infrastructure_device_id == dev.id)
            
            nodes.append({
                'id': node_id,
                'label': dev.hostname or f"Switch-{dev.id}",
                'group': 'switch',
                'title': f"Type: Cisco Enterprise Device<br>Total Links: {attached_count}"
            })
            seen_nodes.add(node_id)

    # 4. INFRASTRUCTURE-TO-INFRASTRUCTURE LINKING ENGINE (VLAN Match + Network Profile Fallback)
    dev_list = list(active_devices)
    links_drawn = set() # Track who we've linked to prevent drawing duplicate lines

    for i, dev_a in enumerate(dev_list):
        for dev_b in dev_list[i+1:]:
            dev_pair = tuple(sorted([dev_a.id, dev_b.id]))
            
            # Match Strategy 1: Look for explicit matching VLAN configurations
            vlans_a = set(PortAttachment.objects.filter(infrastructure_device=dev_a).values_list('vlan_id', flat=True))
            vlans_b = set(PortAttachment.objects.filter(infrastructure_device=dev_b).values_list('vlan_id', flat=True))
            
            shared_vlans = vlans_a.intersection(vlans_b)
            if 1 in shared_vlans and len(shared_vlans) > 1:
                shared_vlans.remove(1) # Focus on explicit custom data VLANs

            if shared_vlans:
                common_vlan = list(shared_vlans)[0]
                edges.append({
                    'from': f"dev_{dev_a.id}",
                    'to': f"dev_{dev_b.id}",
                    'label': f"Trunk (VLAN {common_vlan})",
                    'width': 4,
                    'color': {'color': '#0d6efd'}
                })
                links_drawn.add(dev_pair)
                continue

            # Match Strategy 2: FALLBACK RULES FOR STRIPPED SWITCH CONFIGS
            # If both devices belong to the same parent Network model profile, bind them to the backbone tree
            if dev_pair not in links_drawn and dev_a.network_id == dev_b.network_id:
                
                # Link your Layer-2 edge switches directly up to your Layer-3 network routers
                is_switch_to_router = ('switch' in (dev_a.hostname or '').lower() and 'router' in (dev_b.hostname or '').lower()) or \
                                      ('router' in (dev_a.hostname or '').lower() and 'switch' in (dev_b.hostname or '').lower())
                
                # Or bind peer switches together if they share an isolated tier
                is_switch_peer = 'switch' in (dev_a.hostname or '').lower() and 'switch' in (dev_b.hostname or '').lower()

                if is_switch_to_router or is_switch_peer:
                    edges.append({
                        'from': f"dev_{dev_a.id}",
                        'to': f"dev_{dev_b.id}",
                        'label': 'Uplink Backbone',
                        'width': 4,
                        'color': {'color': '#0d6efd'},
                        'dasharray': [5, 5] # Generates a dashed line style to indicate a derived/trunk path
                    })
                    links_drawn.add(dev_pair)
    return JsonResponse({'nodes': nodes, 'edges': edges})

def host_reachability_matrix(request, host_id):
    """
    Evaluates ACL rules defensively and returns which network nodes are 
    reachable or blocked from the selected host.
    """
    try:
        source_host = Host.objects.get(id=host_id)
    except Host.DoesNotExist:
        return JsonResponse({'error': f'Host ID {host_id} not found'}, status=404)

    # Safety Check: If the source host doesn't have a valid IP, abort cleanly
    if not source_host.ip_address or '.' not in source_host.ip_address:
        return JsonResponse({
            'source_id': f"host_{host_id}",
            'reachable': [],
            'blocked': []
        })

    try:
        # Extract the subnet string segment safely
        source_segments = source_host.ip_address.split('.')
        source_subnet = source_segments[2] if len(source_segments) >= 3 else "unknown_src"
    except Exception as e:
        source_subnet = "unknown_src"

    # Gather all other hosts across the system to evaluate boundaries
    all_hosts = Host.objects.exclude(id=host_id)
    
    reachable_ids = []
    blocked_ids = []

    for target in all_hosts:
        # Safety Check: Skip target endpoints missing an IP string format
        if not target.ip_address or '.' not in target.ip_address:
            continue
            
        try:
            target_segments = target.ip_address.split('.')
            target_subnet = target_segments[2] if len(target_segments) >= 3 else "unknown_tgt"
            
            # Subnet / VLAN separation logic rule simulation
            if source_subnet == target_subnet:
                reachable_ids.append(f"host_{target.id}")
            else:
                blocked_ids.append(f"host_{target.id}")
        except Exception as err:
            logger.error(f"Skipping evaluation row for Host {target.id}: {err}")
            continue

    # ALWAYS returns a clean, valid JSON dictionary layout structure back to Vis.js
    return JsonResponse({
        'source_id': f"host_{host_id}",
        'reachable': reachable_ids,
        'blocked': blocked_ids
    })