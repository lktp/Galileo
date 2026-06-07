# characterization/utils.py
import re
from .models import SecuritySignature, SecurityFinding, ACLRule  # Verify ACLRule is imported here!

def parse_and_scan_config(raw_text, device_config):
    lines = raw_text.splitlines()
    
    # -------------------------------------------------------------------------
    # STEP 1: HOSTNAME EXTRACTION
    # -------------------------------------------------------------------------
    hostname_pattern = re.compile(r"^hostname\s+(\S+)", re.IGNORECASE)
    for line in lines:
        host_match = hostname_pattern.match(line.strip())
        if host_match:
            device_config.hostname = host_match.group(1)
            device_config.save()
            break

    # -------------------------------------------------------------------------
    # STEP 2: NAMED EXTENDED ACL BLOCK PARSER (FOR THE MATRIX GRID)
    # -------------------------------------------------------------------------
    for line in lines:
        clean_line = line.strip().lower()
        
        # Skip empty space breaks or trailing remarks safely
        if not clean_line or clean_line == "!" or clean_line.startswith("remark"):
            continue

        # Isolate token words to evaluate position variables
        tokens = clean_line.split()
        if not tokens:
            continue

        action, protocol, source, destination = None, "ip", None, None

        # --- STYLE A: CLASSIC NUMBERED ACLES (access-list 10-199) ---
        if tokens[0] == "access-list" and len(tokens) >= 3:
            acl_number = tokens[1]
            action = tokens[2] # permit or deny

            if action in ["permit", "deny"]:
                # Check if it's an Extended ACL (100-199) vs Standard ACL (1-99)
                if acl_number.isdigit() and int(acl_number) >= 100:
                    # Extended Format: access-list 101 permit ip [src] [dst]
                    protocol = tokens[3]
                    source = tokens[4]
                    # Target index changes if wildcards are explicitly declared
                    dst_idx = 5 if source == "any" else 6
                    if len(tokens) > dst_idx:
                        destination = tokens[dst_idx]
                else:
                    # Standard Format: access-list 10 permit [src]
                    source = tokens[3]
                    destination = "any" # Standard ACLs imply destination is 'any'

        # --- STYLE B: NESTED NAMED BLOCKS (Inside extended or standard headers) ---
        elif tokens[0] in ["permit", "deny"] and len(tokens) >= 2:
            action = tokens[0]
            
            # Simple heuristic: if the second word is a known protocol, treat as extended
            if tokens[1] in ["ip", "tcp", "udp", "icmp"]:
                protocol = tokens[1]
                source = tokens[2]
                dst_idx = 3 if source == "any" else 4
                if len(tokens) > dst_idx:
                    destination = tokens[dst_idx]
            else:
                # Named Standard: permit 192.168.10.0 0.0.0.255
                source = tokens[1]
                destination = "any"

        # --- DATABASE INGESTION LAYER ---
        if action and source:
            # Clean up trailing subnet wildcard definitions or host prefixes for the matrix keys
            src_clean = "Any" if source == "any" or source == "0.0.0.0" else source
            dst_clean = "Any" if (not destination or destination == "any") else destination

            # Save explicitly to the ACLRule schema engine
            ACLRule.objects.update_or_create(
                device_config=device_config,
                source=src_clean.upper(),
                destination=dst_clean.upper(),
                defaults={
                    'action': action.lower(),
                    'protocol': protocol.lower()
                }
            )

    # -------------------------------------------------------------------------
    # STEP 3: REGEX SECURITY VULNERABILITY SIGNATURE AUDIT SCANNER
    # -------------------------------------------------------------------------
    active_signatures = SecuritySignature.objects.filter(is_active=True)
    for sig in active_signatures:
        matches = re.findall(sig.pattern, raw_text, re.IGNORECASE | re.MULTILINE)
        if matches:
            for match in matches:
                matched_string = match if isinstance(match, str) else str(match)
                
                # Use SecurityFinding since that matches your models.py!
                from .models import SecurityFinding
                SecurityFinding.objects.create(
                    device=device_config,
                    signature=sig,
                    matched_text=matched_string.strip()
                )