from django.db import models

# Create your models here.
# topology/models.py
from django.db import models
from characterization.models import DeviceConfig
from hosts.models import Host

class PortAttachment(models.Model):
    # The Switch or Router providing the connection
    infrastructure_device = models.ForeignKey(DeviceConfig, on_delete=models.CASCADE, related_name='connected_endpoints')
    # The physical interface port identifier
    interface_name = models.CharField(max_length=100, help_text="e.g., GigabitEthernet1/0/21")
    # The connected endpoint host (if resolved by MAC)
    connected_host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='switch_attachments', null=True, blank=True)
    # The raw MAC address detected on that port
    mac_address = models.CharField(max_length=17, help_text="e.g., 001a.a22b.11c4 or 00:1a:a2:2b:11:c4")
    vlan_id = models.IntegerField(default=1)

    class Meta:
        unique_together = ('infrastructure_device', 'interface_name', 'mac_address')

    def __str__(self):
        return f"{self.infrastructure_device.hostname} [{self.interface_name}] -> {self.mac_address}"