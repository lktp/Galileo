import re
from .models import SecuritySignature, SecurityFinding, ACLRule, ArpEntry, RouterObjects, NetworkObject

def is_valid_ip(val):
    """Helper to ensure only valid IPs/Subnets hit the database."""
    # Matches standard IPv4 or CIDR blocks
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', val)

def resolve_nested_objects(name, cache, depth=0):
    """Recursively expand object-groups into a list of raw IPs."""
    if depth > 5: return []

    results = []
    # If it's a known group/object in cache, expand it; otherwise treat as raw IP
    items = cache.get(name, [name])

    for item in items:
        if item in cache:
            results.extend(resolve_nested_objects(item, cache, depth + 1))
        else:
            results.append(item)
    return list(set(results))

def normalize_mac(mac):
    clean = re.sub(r'[\.\:]', '', mac)
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))

def mask_to_cidr(mask):
    try:
        return sum(bin(int(x)).count('1') for x in mask.split('.'))
    except:
        return 24 # Fallback

def get_port_number(port_string):
    # Mapping table for common Cisco aliases
    aliases = {
        "www": 80,
        "http": 80,
        "https": 443,
        "ssh": 22,
        "ftp": 21,
        "telnet": 23,
        "smtp": 25
    }
    
    # If it's already a number
    if port_string.isdigit():
        return int(port_string)
    # If it's an alias
    return aliases.get(port_string.lower(), 0) # Returns 0 if unknown

def extract_segment(p):
        if p >= len(parts): 
            return "any", p
        
        # New "Fast-Path": if the part is "any", consume it and return
        if parts[p] == "any":
            return "any", p + 1
            
        # Check for object-group
        if parts[p] == "object-group":
            if p + 1 < len(parts):
                return f"{parts[p+1]}", p + 2
            return "object-group (incomplete)", p + 1
            
        # Check for host
        if parts[p] == "host":
            if p + 1 < len(parts):
                return f"{parts[p+1]}", p + 2
            return "host (incomplete)", p + 1
            
        # Standard IP + Mask
        if p + 1 < len(parts):
            return f"{parts[p]} {parts[p+1]}", p + 2
        return f"{parts[p]}", p + 1

def save_objects_to_db(objects_json, device_config_instance):
    objects_to_create = []
    
    for obj in objects_json:
        name = obj['name']
        
        # Handle Ports
        for port in obj.get('ports', []):
            objects_to_create.append(NetworkObject(
                device_config=device_config_instance,
                group_name=name,
                member_type='port',
                value=str(port)
            ))
            
        # Handle IP Addresses/Subnets
        for addr in obj.get('addresses', []):
            # Format: '10.10.10.0/24'
            cidr = f"{addr['ip']}/{addr['subnet']}"
            objects_to_create.append(NetworkObject(
                device_config=device_config_instance,
                group_name=name,
                member_type='address',
                value=cidr
            ))
            
    NetworkObject.objects.bulk_create(objects_to_create)



#dedicated object parser
def parse_object_json(raw_text):
    data = {}
    current_context = None
    active_name = None
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    
    lines = raw_text.splitlines() # Do NOT strip() yet

    for line in lines:
        # 1. Detect Start
        if line.startswith("object-group"):
            current_context = 'object'
            active_name = line.split()[-1]
            if active_name not in data: data[active_name] = []
            continue
            
        # 2. Detect Boundary (If we are in an object, and line doesn't start with space)
        if current_context == 'object':
            if line.startswith(" "):
                data[active_name].append(line.strip())
            else:
                current_context = None # Stop capturing
                
    print(data)
    # ... rest of the processing logic (ports/addresses) stays the same
    final_objs = []
    for name, content in data.items():
        addresses = []
        for l in content:
            # 1. Look specifically for 'host' entries - these ARE /32
            if "host " in l.lower():
                parts = l.split()
                # Assuming format: "host 192.168.50.10"
                addresses.append({"ip": parts[1], "subnet": 32})
                continue
            
            # 2. Look for network blocks - these should be /24 or whatever the mask is
            # We split and check if the second element is a valid mask
            parts = l.split()
            if parts and re.match(ip_pattern, parts[0]):
                # If there's a second part, convert it; otherwise it's a default /24
                if len(parts) >= 2:
                    # Check if the second part looks like an IP mask
                    if "." in parts[1]:
                        subnet = mask_to_cidr(parts[1])
                    else:
                        subnet = 24 # Fallback if not a mask
                else:
                    subnet = 24
                
                addresses.append({"ip": parts[0], "subnet": mask_to_cidr(subnet)})

        ports = [get_port_number(match.group(1)) for l in content for match in [re.search(r'eq (\S+)', l)] if match]
        final_objs.append({"name": name, "ports": ports, "addresses": addresses})
        
    return final_objs

# 3. Dedicated Interface Parser (With restored subnet logic)
def parse_interface_json(raw_text):
    data = {}
    active_name = None
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    for line in lines:
        if line.startswith("interface"):
            active_name = line.split()[1]
            data[active_name] = []
        elif active_name:
            data[active_name].append(line)
            
    final_ints = []
    for name, content in data.items():
        ip_line = next((l for l in content if "ip address" in l), None)
        if ip_line:
            parts = ip_line.split()
            # Restored: Check index, use mask, or default to 24
            subnet = mask_to_cidr(parts[3]) if len(parts) >= 4 else 24
            final_ints.append({"name": name, "address": [{"ip": parts[2], "subnet": subnet}]})
        else:
            final_ints.append({"name": name, "address": []})
    return final_ints


#The below functions serve to do stuff for the ACLs.

def save_json_to_db_acls(json_data, device_config_instance):
    acl_rules_to_create = []
    
    for acl_group in json_data:
        name = acl_group['name']
        
        for rule in acl_group['rules']:
            # Create an instance of your model (without saving to DB yet)
            new_rule = ACLRule(
                device_config=device_config_instance,
                acl_name=name,
                action=rule['action'],
                protocol=rule['protocol'],
                source=rule['source'],
                destination=rule['destination'],
                # You might need to add logic to extract the port from 'service'
                destination_port=rule['service'] 
            )
            acl_rules_to_create.append(new_rule)
            
    # Use Django's bulk_create for high performance
    ACLRule.objects.bulk_create(acl_rules_to_create)

def parse_acl_line(parts):
    # Default values
    # access-list CSM_FW_ACL_ advanced permit tcp ifc NAV-DMZ object-group GRP-HST-NAV-HOSTS host 169.55.82.21 eq https rule-id 268436502

    if "advanced" in parts[0] or "extended" in parts[0]:
        del parts[0]

    if "ifc" in parts:
        idx = parts.index("ifc")

        # 2. Remove the current item and the one after it
        # We remove index (idx + 1) first to avoid shifting issues,
        # then remove idx.
        parts.pop(idx + 1) # Removes the item AFTER 'advanced'
        parts.pop(idx)

    rule = {"action": parts[0], "protocol": "", "source": "any", "destination": "any", "service": "any"}


    # 1. Protocol Detection
    proto_list = ["tcp", "udp", "icmp", "ip", "gre", "ipinip"]
    ptr = 1 # Start pointer at index 1 (right after action)
    
    if len(parts) > 1 and parts[1].lower() in proto_list:
        rule["protocol"] = parts[1].lower()
        ptr = 2 # Advance pointer to skip protocol
    
    # 2. Safe Segment Extractor
    def extract_segment(p):
        if p >= len(parts): 
            return "any", p
        
        # Check for object-group (requires 2 parts: keyword + name)
        if parts[p] == "object-group":
            if p + 1 < len(parts):
                return f"object-group {parts[p+1]}", p + 2
            return "object-group (incomplete)", p + 1
            
        # Check for host (requires 2 parts: keyword + ip)
        if parts[p] == "host":
            if p + 1 < len(parts):
                return f"{parts[p+1]}", p + 2
            return "host (incomplete)", p + 1
            
        # Standard IP + Mask
        if p + 1 < len(parts):
            if parts[p] != "any":
                return f"{parts[p]}/{mask_to_cidr(parts[p+1])}", p + 2
            else:
                return "0.0.0.0", p+1
        return f"{parts[p]}", p + 1

    # 4. Remaining is service
    if ptr < len(parts):
        rule["service"] = " ".join(parts[ptr:])
    elif "range" in parts:
        idx = parts.index("range")
        parts.pop(idx)
        rule["service"] = f"{parts[idx-1]} - {parts[idx]}"


    # 3. Parse Source and Destination
    rule["source"], ptr = extract_segment(ptr)
    rule["destination"], ptr = extract_segment(ptr)


    return rule

#  Dedicated ACL Parser
def parse_to_ACL_json(raw_text):
    data = {}
    lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
    current_name = None

    for line in lines:
        if line.startswith("ip access-list"):
            current_name = line.split()[-1]
            data[current_name] = []
        elif line.startswith(("permit", "deny")) and current_name:
            data[current_name].append(parse_acl_line(line.split()))
        elif line.startswith("access-list") and not "remark" in line:
            parts = line.split()
            name = parts[1]
            if name not in data: data[name] = []
            data[name].append(parse_acl_line(parts[2:]))
            
    return [{"name": name, "rules": rules} for name, rules in data.items()]

def resolve_acl_json(acl_json, device_instance):
    # Create a deep copy to avoid modifying the original data unexpectedly
    import copy
    resolved_json = copy.deepcopy(acl_json)
    
    for acl in resolved_json:
        for rule in acl['rules']:
            # Fields to check for object-group replacement
            fields_to_check = ['source', 'destination', 'service']
            
            for field in fields_to_check:
                value = rule.get(field, "")
                
                # Check if the string starts with "object-group"
                if value.startswith("object-group"):
                    # Extract the group name (e.g., "object-group WEB_TRAFFIC" -> "WEB_TRAFFIC")
                    parts = value.split(" ", 1)
                    if len(parts) > 1:
                        group_name = parts[1]
                        
                        # Fetch members from DB
                        members = NetworkObject.objects.filter(
                            group_name=group_name, 
                            device_config=device_instance
                        ).values_list('value', flat=True)
                        
                        # Replace the string with a comma-separated list of IPs/Ports
                        if members:
                            rule[field] = ", ".join(list(members))
                            
    return resolved_json


def parse_and_scan_config(raw_text, device_config):
    OBJECTS_JSON = parse_object_json(raw_text)
    ACL_JSON=parse_to_ACL_json(raw_text)
    INTERFACE_JSON=parse_interface_json(raw_text)

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    #print(f"Object Json: {OBJECTS_JSON}")
    #print(f"Interface Json: {INTERFACE_JSON}")
    # Main Parsing Loop
    
    save_objects_to_db(OBJECTS_JSON, device_config)

    resolve_acl_json(ACL_JSON, device_config)
    #print (ACL_JSON)
    save_json_to_db_acls(ACL_JSON, device_config)


    # 3. Security Scan
    for sig in SecuritySignature.objects.filter(is_active=True):
        matches = re.findall(sig.pattern, raw_text, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            SecurityFinding.objects.create(device=device_config, signature=sig, matched_text=str(match))


def parse_cisco_arp(raw_text, device_config):
    arp_pattern = re.compile(r"Internet\s+([0-9.]+)\s+\S+\s+([0-9a-fA-F\.]+)\s+ARPA")
    for line in raw_text.splitlines():
        match = arp_pattern.search(line.strip())
        if match:
            ip, mac = match.groups()
            ArpEntry.objects.update_or_create(ip_address=ip, gathered_from=device_config,
                                              defaults={'mac_address': normalize_mac(mac)})
