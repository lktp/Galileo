import xml.etree.ElementTree as ET
from .models import Host, OpenPort

# ADDED: network_obj parameter passed from the view controller
def parse_nmap_xml(xml_content_string, network_obj=None):
    try:
        root = ET.fromstring(xml_content_string)
    except ET.ParseError:
        return {"status": "error", "message": "Invalid XML structure string parsed."}

    hosts_imported = 0

    for host_node in root.findall('host'):
        status = host_node.find('status')
        if status is not None and status.get('state') != 'up':
            continue

        ip_address = None
        for addr in host_node.findall('address'):
            if addr.get('addrtype') == 'ipv4' or addr.get('addrtype') == 'ipv6':
                ip_address = addr.get('addr')
                break

        if not ip_address:
            continue

        hostname = ""
        hostnames_node = host_node.find('hostnames')
        if hostnames_node is not None:
            hostname_node = hostnames_node.find('hostname')
            if hostname_node is not None:
                hostname = hostname_node.get('name')

        os_name = "Unknown OS"
        os_node = host_node.find('os')
        if os_node is not None:
            os_match = os_node.find('osmatch')
            if os_match is not None:
                os_name = os_match.get('name')

        # UPDATED: We now map the network target parameter here
        host_obj, _ = Host.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'network': network_obj, # Assigns the foreign key association relationship
                'hostname': hostname if hostname else None,
                'os_name': os_name
            }
        )
        hosts_imported += 1

        # 3. Extract Open Ports & Active Service Fingerprints
        ports_node = host_node.find('ports')
        if ports_node is not None:
            for port_node in ports_node.findall('port'):
                state_node = port_node.find('state')
                
                # We only want to track open or active services
                if state_node is not None and state_node.get('state') == 'open':
                    port_number = int(port_node.get('portid'))
                    protocol = port_node.get('protocol')
                    
                    service_node = port_node.find('service')
                    service_name = service_node.get('name') if service_node is not None else "unknown"
                    product = service_node.get('product') if service_node is not None else None
                    version = service_node.get('version') if service_node is not None else None

                    # Dynamically commit service mappings cleanly
                    OpenPort.objects.update_or_create(
                        host=host_obj,
                        port_number=port_number,
                        protocol=protocol,
                        defaults={
                            'service_name': service_name,
                            'product': product,
                            'version': version,
                            'state': 'open'
                        }
                    )

    return {"status": "success", "hosts_processed": hosts_imported}