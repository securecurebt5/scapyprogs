scapyprogs
==========

Here is another program that I have wrote in python using scapy module, simply
this particular code sends dhcp discover messages and waits for a dhcp offer message
and check if the source is the legal DHCP server or not, if not it prints to the user
that a Rogue DHCP server is in the network.
Reauired :
    scapy
    colorama
Usage:
  Rogue_DHCP_Checker.py <legal_dhcp server_IP>
  
