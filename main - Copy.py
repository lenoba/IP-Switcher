import subprocess
import admin

if not admin.isUserAdmin():
	admin.runAsAdmin()


def set_ip(name,ip,mask='255.255.255.0',gw=None,dns='DHCP'):
	if ip == 'DHCP':
		subprocess.Popen('netsh interface ip set address "'+name+'" dhcp')
	else:
		if not gw:
			gw = ip[:ip.rfind('.')]+'.1'
		subprocess.Popen('netsh interface ip set address "'+name+'" static '+ip+' '+mask+' '+gw+' 1')

	if type(dns) == type("string"):
		subprocess.Popen('netsh interface ip add dns "'+name+'" '+dns)

def get_conf():
	nic_list = {}
	p = subprocess.Popen('ipconfig /all', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	name = 'Woot'
	dns_list = False
	for num, line in enumerate(p.stdout.readlines()):
		if line.lstrip().startswith('IPv4 Address'):
			ip = line.rstrip()[line.find(':')+2:]
			ip = ip[:ip.find('(Prefe')]
			nic_list[name]['IP'] = ip
		if line.lstrip().startswith('Subnet Mask'):
			nic_list[name]['MASK'] = line.rstrip()[line.find(':')+2:]
		if line.lstrip().startswith('Default Gateway'):
			nic_list[name]['Gateway'] = line.rstrip()[line.find(':')+2:]
		if line.lstrip().startswith("NetBIOS"):
			dns_list = False
		if dns_list:
			nic_list[name]['DNS'].append(line.strip())
		if line.lstrip().startswith('DNS Servers'):
			dns_list = True
			nic_list[name]['DNS'] = [line.rstrip()[line.find(':')+2:]]
		if line.lstrip().startswith('DHCP Server'):
			nic_list[name]['DHCP Server'] = line.rstrip()[line.find(':')+2:]

		if line.startswith(' ') or line.strip() == '' or num<2:
			continue
		name =line[line.find("adapter ")+8:-3]
		nic_list[name] = {}
		return nic_list

debug_output = True
nic_list = {}

p = subprocess.Popen('ipconfig /all', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
doing = False
name = 'Woot'
dns_list = False
for num, line in enumerate(p.stdout.readlines()):
	if line.lstrip().startswith('IPv4 Address'):
		ip = line.rstrip()[line.find(':')+2:]
		ip = ip[:ip.find('(Prefe')]
		nic_list[name]['IP'] = ip
	if line.lstrip().startswith('Subnet Mask'):
		nic_list[name]['MASK'] = line.rstrip()[line.find(':')+2:]
	if line.lstrip().startswith('Default Gateway'):
		nic_list[name]['Gateway'] = line.rstrip()[line.find(':')+2:]
	if line.lstrip().startswith("NetBIOS"):
		dns_list = False
	if dns_list:
		nic_list[name]['DNS'].append(line.strip())
	if line.lstrip().startswith('DNS Servers'):
		dns_list = True
		nic_list[name]['DNS'] = [line.rstrip()[line.find(':')+2:]]
	if line.lstrip().startswith('DHCP Server'):
		nic_list[name]['DHCP Server'] = line.rstrip()[line.find(':')+2:]


	if line.startswith(' ') or line.strip() == '' or num<2:
		continue
	name =line[line.find("adapter ")+8:-3]
	nic_list[name] = {}
retval = p.wait()

import pprint
pprint.pprint(nic_list)

ip = "192.168.1.197"
mask = "255.255.255.0"
gateway = "192.168.1.1"

set_ip("WiFi",ip, mask, gateway, '8.8.8.8')
#set_ip("WiFi","DHCP")