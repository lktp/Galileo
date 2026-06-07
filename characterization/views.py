from django.shortcuts import render, get_object_or_404, redirect
from .models import Network, ACLRule, DeviceConfig, SecurityFinding, SignatureBackup, SecuritySignature
from .utils import parse_and_scan_config
from django.urls import reverse
from topology.utils import parse_switch_ports_and_cam

def toggle_signature_active(request, sig_id):
    """Enables or disables a scanning rule globally."""
    sig = get_object_or_404(SecuritySignature, id=sig_id)
    sig.is_active = not sig.is_active
    sig.save()
    status = "activated" if sig.is_active else "deactivated"
    messages.success(request, f"Signature '{sig.rule_name}' successfully {status}.")
    return redirect('signatures_dashboard')


def signatures_dashboard_view(request):
    """
    Renders the main dashboard showing all security audit signatures,
    their matching regex patterns, and handles new signature registration.
    """
    # If the user fills out the "Create New Signature" form on the dashboard page
    if request.method == 'POST':
        rule_name = request.POST.get('rule_name', '').strip().upper()
        pattern = request.POST.get('pattern', '').strip()
        severity = request.POST.get('severity', 'Medium')
        description = request.POST.get('description', '').strip()

        if rule_name and pattern:
            try:
                SecuritySignature.objects.create(
                    rule_name=rule_name,
                    pattern=pattern,
                    severity=severity,
                    description=description
                )
                messages.success(request, f"Security signature '{rule_name}' successfully deployed.")
            except Exception as e:
                messages.error(request, f"Error creating signature: Name might already exist. ({e})")
        else:
            messages.error(request, "Failed to create signature. Rule Name and Regex Pattern are required.")
        
        return redirect('signatures_dashboard')

    # GET Request: Fetch all signatures from the database
    # .prefetch_related('backups') keeps the database queries highly efficient!
    signatures = SecuritySignature.objects.all().prefetch_related('backups').order_by('rule_name')

    context = {
        'signatures': signatures,
        'severity_choices': ['High', 'Medium', 'Low']
    }
    return render(request, 'characterization/signatures_dashboard.html', context)

def backup_signature(request, sig_id):
    """Freezes the current regex pattern state to the history database."""
    sig = get_object_or_404(SecuritySignature, id=sig_id)
    SignatureBackup.objects.create(
        original_signature=sig,
        version=sig.version,
        pattern_snapshot=sig.pattern,
        severity_snapshot=sig.severity,
        description_snapshot=sig.description,
        notes="User manual snapshot backup."
    )
    messages.success(request, f"Backup point captured for '{sig.rule_name}' (Version {sig.version}).")
    return render(request, 'characterization/signatures_dashboard.html', context)

def restore_signature(request, backup_id):
    """Rolls back the live scanner regex string to an old version."""
    backup = get_object_or_404(SignatureBackup, id=backup_id)
    sig = backup.original_signature
    
    # Auto-backup the current state so you never lose anything during a rollback
    SignatureBackup.objects.create(
        original_signature=sig,
        version=sig.version,
        pattern_snapshot=sig.pattern,
        severity_snapshot=sig.severity,
        description_snapshot=sig.description,
        notes=f"Automatic safety backup before rollback to v{backup.version}."
    )
    
    # Overwrite live rules with historical assets
    sig.pattern = backup.pattern_snapshot
    sig.severity = backup.severity_snapshot
    sig.description = backup.description_snapshot
    sig.version += 1
    sig.save()
    
    messages.success(request, f"Successfully restored '{sig.rule_name}' to version {backup.version}!")
    return render(request, 'characterization/signatures_dashboard.html', context)


def network_detail_view(request, network_id):
    network_obj = get_object_or_404(Network, pk=network_id)
    
    if request.method == 'POST':
        uploaded_file = request.FILES.get('config_file')
        file_type = request.POST.get('file_type', 'config') # Grab toggle value

        if uploaded_file:
            raw_text = uploaded_file.read().decode('utf-8')
            
            if file_type == 'cam_table':
                device_config, _ = DeviceConfig.objects.get_or_create(
                    network=network_obj,
                    hostname=f"Switch-{network_id}"
                )
                parse_switch_ports_and_cam(raw_text, device_config)
            else:
                # 1. Dynamically extract the actual hostname from the file text body
                hostname_match = re.search(r"^hostname\s+(\S+)", raw_text, re.MULTILINE | re.IGNORECASE)
                extracted_hostname = hostname_match.group(1) if hostname_match else "Unknown-Device"

                # 2. Prevent duplicate ghost boxes by grabbing or updating the record
                device_config, created = DeviceConfig.objects.update_or_create(
                    network=network_obj,
                    hostname=extracted_hostname,
                    defaults={'config_file': uploaded_file}
                )
                
                # 3. Run your standard security/ACL scanner
                parse_and_scan_config(raw_text, device_config)
                
                # 4. Run your topology interface mapping parser
                parse_switch_ports_and_cam(raw_text, device_config)
                
            return redirect(f'/cisco/network/{network_id}/')

    # (Leave your standard context rendering variables below this untouched)
    return render(request, 'characterization/network_detail.html', {'network': network_obj})

def global_dashboard_view(request):
    # Pull signature counts from your tracking engine
    total_signatures = SecuritySignature.objects.count()
    active_signatures = SecuritySignature.objects.filter(is_active=True).count()
    
    # Severity counters for active rules
    high_sigs = SecuritySignature.objects.filter(severity='High', is_active=True).count()
    med_sigs = SecuritySignature.objects.filter(severity='Medium', is_active=True).count()
    low_sigs = SecuritySignature.objects.filter(severity='Low', is_active=True).count()

    cisco_stats = {
        'total_networks': Network.objects.count(),
        'total_configs': DeviceConfig.objects.count(),
        'total_findings': SecurityFinding.objects.count(),
        
        # New Engine Statistics
        'sig_total': total_signatures,
        'sig_active': active_signatures,
        'sig_high': high_sigs,
        'sig_med': med_sigs,
        'sig_low': low_sigs,
    }

    # Pulling context parameters for your existing networks loops...
    networks = Network.objects.all()

    context = {
        'cisco_stats': cisco_stats,
        'networks': networks,
        # ... keep any other network routing variables you have here ...
    }
    return render(request, 'char/index_dashboard.html', context)

def network_dashboard_view(request):
    if request.method == 'POST':
        network_name = request.POST.get('network_name')
        network_desc = request.POST.get('network_description')
        uploaded_file = request.FILES.get('config_file')
        hostname = request.POST.get('hostname', 'Unknown-Device')

        if network_name and uploaded_file:
            network, _ = Network.objects.get_or_create(
                name=network_name,
                defaults={'description': network_desc}
            )
            
            device_config = DeviceConfig.objects.create(
                network=network,
                hostname=hostname,
                config_file=uploaded_file
            )

           
            uploaded_file.seek(0) 

            try:
                raw_bytes = uploaded_file.read()
                raw_text = raw_bytes.decode('utf-8-sig')
            except UnicodeDecodeError:
                raw_text = raw_bytes.decode('latin-1')
            
            # Now raw_text will contain your actual configuration payload!
            parse_and_scan_config(raw_text, device_config)
            parse_switch_ports_and_cam(raw_text, device_config)
            return redirect(f"/network/?network_id={network.id}")
    # --- RETRIEVE METRICS (GET) ---
    networks = Network.objects.all().order_by('-created_at')
    selected_network_id = request.GET.get('network_id')
    selected_network = None
    unique_destinations = []
    grid_rows = []
    network_findings = []

    if selected_network_id:
        selected_network = get_object_or_404(Network, pk=selected_network_id)
        rules = ACLRule.objects.filter(device_config__network=selected_network)
        network_findings = SecurityFinding.objects.filter(device__network=selected_network).select_related('device', 'signature')
        #network_findings = SecurityFinding.objects.filter(device__network=network_obj).select_related('device', 'signature')
        #network_findings = SecurityFinding.objects.filter(device_config__network=selected_network).order_by('-severity')

        sources = sorted(list(set(rule.source for rule in rules)))
        unique_destinations = sorted(list(set(rule.destination for rule in rules)))
        lookup_table = {f"{r.source}||{r.destination}": r.action.lower() for r in rules}
        
        for src in sources:
            row_cells = []
            for dst in unique_destinations:
                status = lookup_table.get(f"{src}||{dst}", "none")
                row_cells.append({'destination': dst, 'status': status})
            grid_rows.append({'source': src, 'cells': row_cells})

    context = {
        'networks': networks,
        'selected_network': selected_network,
        'unique_destinations': unique_destinations,
        'grid_rows': grid_rows,
        'network_findings': network_findings,
    }
    return render(request, 'characterization/dashboard.html', context)

def network_matrix_view(request, network_id):
    network = get_object_or_404(Network, pk=network_id)
    rules = ACLRule.objects.filter(device_config__network=network)
    
    sources = sorted(list(set(rule.source for rule in rules)))
    destinations = sorted(list(set(rule.destination for rule in rules)))
    
    # Build a flat dictionary where keys are "source_ip||dst_ip"
    matrix_data = {}
    for rule in rules:
        key = f"{rule.source}||{rule.destination}"
        matrix_data[key] = rule.action.lower()

    context = {
        'network': network,
        'unique_sources': sources,
        'unique_destinations': destinations,
        'matrix_data': matrix_data,
    }
    return render(request, 'characterization/acls.html', context)

