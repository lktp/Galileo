# models.py
from django.db import models

class Network(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class DeviceConfig(models.Model):
    # CHANGED: rel_name -> related_name
    network = models.ForeignKey(Network, on_delete=models.CASCADE, related_name="configs")
    hostname = models.CharField(max_length=100, blank=True)
    config_file = models.FileField(upload_to='configs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

class InfrastructureLink(models.Model):
    # The source (Local)
    source_device = models.ForeignKey(DeviceConfig, on_delete=models.CASCADE, related_name='uplinks')
    source_interface = models.CharField(max_length=100)

    # The target (Remote/Neighbor)
    target_device = models.ForeignKey(DeviceConfig, on_delete=models.SET_NULL, null=True, related_name='downlinks')
    target_interface = models.CharField(max_length=100, blank=True)

    # Metadata for the link
    vlan_list = models.CharField(max_length=255, blank=True)
    last_discovered = models.DateTimeField(auto_now=True)

    class Meta:
        # Prevents duplicate links for the same interface
        unique_together = ('source_device', 'source_interface')
    
class Subnet(models.Model):
    # This creates the key relationship (ForeignKey)
    # on_delete=models.CASCADE ensures if a Network is deleted, 
    # its subnets are removed too.
    network = models.ForeignKey(
        Network, 
        on_delete=models.CASCADE, 
        related_name='subnets'
    )
    cidr_block = models.CharField(max_length=50) # e.g., '10.0.0.0/24'
    name = models.CharField(max_length=100, blank=True) # e.g., 'Internal_Users'

    class Meta:
            # Ensures you don't accidentally add the same CIDR 
            # to the same network twice
            unique_together = ('network', 'cidr_block')

class NetworkObject(models.Model):
    device_config = models.ForeignKey(DeviceConfig, on_delete=models.CASCADE)
    group_name = models.CharField(max_length=100)
    # Store either a port number OR an IP/Subnet string
    member_type = models.CharField(max_length=20) # 'port' or 'address'
    value = models.CharField(max_length=100)



class ArpEntry(models.Model):
    # Use 17 for standard MAC (00:00:00:00:00:00)
    mac_address = models.CharField(max_length=17) 
    # Use 15 for standard IPv4 (255.255.255.255)
    ip_address = models.GenericIPAddressField() 
    
    gathered_from = models.ForeignKey(
        DeviceConfig,
        on_delete=models.CASCADE,
        related_name='arp_entries' # This makes more sense!
    )

    class Meta:
        # Ensures you don't have multiple entries for the same IP on one device
        unique_together = ('ip_address', 'gathered_from')

    def __str__(self):
        return f"{self.ip_address} -> {self.mac_address}"

class ACLRule(models.Model):
    device_config = models.ForeignKey(DeviceConfig, on_delete=models.CASCADE, related_name="acl_rules")
    acl_name = models.CharField(max_length=100)
    action = models.CharField(max_length=10) # permit/deny
    protocol = models.CharField(max_length=20)
    # These now store the resolved IP or object name
    source = models.CharField(max_length=255)
    destination = models.CharField(max_length=255)
    destination_port = models.CharField(max_length=50, blank=True)

class RouterObjects(models.Model):
    device_config = models.ForeignKey(DeviceConfig, on_delete=models.CASCADE, related_name="router_objects")
    object_name = models.CharField(max_length=100)
    object_type = models.CharField(max_length=255, default='Network') # Removed the broken 'choice='
    contents = models.TextField() # Changed to TextField for longer group lists
    device_config = models.ForeignKey(DeviceConfig, on_delete=models.CASCADE, related_name="routerObjects")

    def __str__(self):
        return f"{self.object_name} ({self.object_type})"


class SecuritySignature(models.Model):
    SEVERITY_CHOICES = [
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    rule_name = models.CharField(max_length=100, unique=True, help_text="e.g., TELNET_ENABLED")
    pattern = models.CharField(max_length=255, help_text="The regular expression pattern to match against.")
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='Medium')
    description = models.TextField(help_text="Detailed context shown to the user on findings.")
    is_active = models.BooleanField(default=True, help_text="Easily toggle this signature rule on/off.")
    def __str__(self):
        return f"{self.rule_name} ({self.severity})"


class SignatureBackup(models.Model):
    """Stores historical regex patterns for quick recovery points."""
    original_signature = models.ForeignKey(SecuritySignature, on_delete=models.CASCADE, related_name='backups')
    version = models.IntegerField()
    pattern_snapshot = models.CharField(max_length=255)
    severity_snapshot = models.CharField(max_length=10)
    description_snapshot = models.TextField()
    backed_up_at = models.DateTimeField(auto_now_add=True)
    notes = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ['-backed_up_at']

class SecurityFinding(models.Model):
    # THE LINK: Connects the security finding directly to the specific machine scanned
    device = models.ForeignKey(
        DeviceConfig, 
        on_delete=models.CASCADE, 
        related_name='findings',
        null=True,
        blank=True
    )
    signature = models.ForeignKey(SecuritySignature, on_delete=models.CASCADE)
    matched_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        device_name = self.device.hostname if (self.device and self.device.hostname) else "Unknown Device"
        return f"{self.signature.rule_name} found on {device_name}"
