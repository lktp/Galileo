import re
from .models import SecuritySignature, SecurityFinding, ACLRule, ArpEntry, RouterObjects

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

def parse_and_scan_config(raw_text, device_config):
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

    # 1. PASS 1: Index Objects/Groups
    object_cache = {}
    current_obj = None
    for line in lines:
        obj_match = re.match(r"object(?:-group)? (?:network|service) (\S+)", line)
        if obj_match:
            current_obj = obj_match.group(1)
            object_cache[current_obj] = []
            continue
        if current_obj and (line.startswith("network-object") or line.startswith("port-object")):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                object_cache[current_obj].append(parts[1])
        elif line.startswith("!"):
            current_obj = None

    # Persist objects to DB
    for name, values in object_cache.items():
        RouterObjects.objects.update_or_create(
            device_config=device_config,
            object_name=name,
            defaults={'contents': ", ".join(values)}
        )


    # 2. PASS 2: Robust Resolution
    # Get a list of valid cache keys, sorted by length descending (to match long names first)
    cache_keys = sorted(object_cache.keys(), key=len, reverse=True)

    # Updated PASS 2 logic
    for line in lines:
        # 1. Check for BOTH permit and deny
        is_permit = "permit" in line
        is_deny = "deny" in line

        if "access-list" in line and (is_permit or is_deny):
            action = "permit" if is_permit else "deny"

            # Find which cache keys exist in this line
            found_keys = [k for k in cache_keys if k in line]

            if len(found_keys) >= 2:
                src_name = found_keys[0]
                dst_name = found_keys[1]

                src_list = resolve_nested_objects(src_name, object_cache)
                dst_list = resolve_nested_objects(dst_name, object_cache)

                for s in src_list:
                    for d in dst_list:
                        if re.match(r'^\d{1,3}(\.\d{1,3}){3}', s) and re.match(r'^\d{1,3}(\.\d{1,3}){3}', d):
                            ACLRule.objects.update_or_create(
                                device_config=device_config,
                                source=s,
                                destination=d,
                                # 2. Use the dynamically determined action
                                defaults={'action': action, 'protocol': 'ip', 'acl_name': 'CSM_FW_ACL'}
                            )

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
