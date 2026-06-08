from django.db import models
from characterization.models import Network 

class Host(models.Model):
    # THE LINK: Connects each host directly to a network profile.
    # null=True allows you to handle standalone or stray hosts if needed.
    network = models.ForeignKey(
        Network, 
        on_delete=models.CASCADE, 
        related_name='hosts', 
        null=True, 
        blank=True
    )
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    os_name = models.CharField(max_length=100, blank=True, null=True)
    last_seen = models.DateTimeField(auto_now=True)
    mac_address = models.CharField(max_length=17, blank=True, null=True, unique=True)
    
    def __str__(self):
        return self.hostname or self.ip_address

class OpenPort(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='open_ports')
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp') # tcp, udp
    service_name = models.CharField(max_length=100, blank=True, null=True) # e.g., ssh, http, netbios
    product = models.CharField(max_length=255, blank=True, null=True) # e.g., OpenSSH, Apache httpd
    version = models.CharField(max_length=100, blank=True, null=True) # e.g., 8.9p1
    state = models.CharField(max_length=20, default='open')
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('host', 'port_number', 'protocol')

    def __str__(self):
        return f"{self.host} - {self.port_number}/{self.protocol} ({self.state})"