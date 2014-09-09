#!/usr/bin/env python
# Author : KADDOUR BOUMEDIENE
# NAME : Rogue_DHCP_Checker.py
# Purpose : Check if a Rogue DHCP Server running on the network
 
from scapy.all import *
import threading
from colorama import Back
from sys import argv
from time import sleep 

# set 'hack1' as the default interface
#conf.iface = 'hack1'
# create a global lock var to prevent threads to be executed while another thread is running 
global lock
lock = threading.Lock()

# This Function Create the BOOTP message(packet, DHCP Discover)

def BootpPacket():
	fm, hw = get_if_raw_hwaddr(scapy.all.conf.iface)
	ether=Ether(dst="ff:ff:ff:ff:ff:ff")
	ip=IP(src="0.0.0.0",dst="255.255.255.255")
	udp=UDP(sport=68,dport=67)
	bootp=BOOTP(chaddr=hw)
	dhcp=DHCP(options=[("message-type","discover"),"end"])
	DHCPDiscover = ether/ip/udp/bootp/dhcp
	return DHCPDiscover	
# This Function Sends the DHCP Discover Message on the Network searching for new DHCP Servers

def sendpkt(DHCPDiscover):
	srp(DHCPDiscover,timeout=2,inter=5, verbose=0)
	a = sniff(prn=test)
	# Thread2 for sniffing BOOTP Message on the network (DHCP OFFER MSG)
	t2 = threading.Thread(target=test)
	t2.start()

DHCPDiscover = BootpPacket()
def test(pkt):
	if pkt.haslayer(BOOTP):
		if pkt[IP].src != "0.0.0.0" and pkt[IP].src != LegalDHCPServer and pkt[BOOTP].op ==2:
			if pkt[IP].src not in dhcpservers:
				try:
					lock.acquire()
					print "Rogue DHCP Server(hacker) is at " + Back.RED+"%s"%pkt[IP].src+Back.RESET
					dhcpservers.add(pkt[IP].src)
				except :
					lock.acquire()
				finally:
					lock.release()
			else:	
				pass
		else:
			
			if pkt[IP].src not in legalservers:	
				try:
					lock.acquire()
					print "Legal DHCP Server:%s"%pkt[IP].src				
					legalservers.add(pkt[IP].src)
				except:
					lock.acquire()
				finally:
					lock.release()
			else:
				pass
	else:
		pass
legalservers = set()
dhcpservers = set()
while True:
	# Thread1 that sends DHCP Discover MSGs
	if len(argv) != 2:
		print 'Usage: %s <LegalServersIP>'%argv[0]
		exit(0)
	else:			
		LegalDHCPServer = argv[1]
		t = threading.Thread(target=sendpkt,args=DHCPDiscover)
		t.start()
		sleep(5)		
