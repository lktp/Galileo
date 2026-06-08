
from characterization.models import ArpEntry 
from hosts.models import Host
from topology.models import PortAttachment

def reconcile_network_topology():
    """
    Stitches together IP-based inventory (Host) with Layer 2 visibility (ArpEntry).
    """
    
    # 1. Update/Populate Hosts based on ARP Data
    # ARP data is the most reliable way to link an IP to a specific MAC
    for arp in ArpEntry.objects.all():
        host, created = Host.objects.get_or_create(ip_address=arp.ip_address)
        
        # If the host didn't have a MAC address or it changed, update it
        if host.mac_address != arp.mac_address:
            host.mac_address = arp.mac_address
            host.save()
            print(f"[+] Updated Host {host.ip_address} with MAC {arp.mac_address}")

    # 2. Connect the dots: Link PortAttachment to Host
    # This aligns the physical switch port with the discovered machine
    for attachment in PortAttachment.objects.all():
        if attachment.mac_address:
            # Find the host record that matches the MAC address from the switch CAM table
            try:
                matching_host = Host.objects.get(mac_address=attachment.mac_address)
                attachment.connected_host = matching_host
                attachment.save()
            except Host.DoesNotExist:
                # If we have a MAC on a switch port but no Host record, 
                # this is likely a device that hasn't been scanned or is silent
                continue
    
    print("[+] Topology reconciliation completed successfully.")