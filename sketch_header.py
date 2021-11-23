
from scapy.all import *
import sys, os

TYPE_SKETCH = 0x90
#TYPE_UDP = 0x11

class SketchSelection(Packet):
    name = "SketchSelection"
    fields_desc = [
        BitField("NMI", 0, 5),
        BitField("pos", 0, 3)
    ]
    def mysummary(self):
        return self.sprintf("NMI=%NMI%, pos=%pos%")


bind_layers(IP, SketchSelection, proto=TYPE_SKETCH)
#bind_layers(SketchSelection, UDP, protocol=TYPE_UDP)
