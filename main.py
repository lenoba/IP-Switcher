import subprocess
import time
import ctypes,sys, enum

#if not admin.isUserAdmin():
#	admin.runAsAdmin()



class SW(enum.IntEnum):
    HIDE = 0
    MAXIMIZE = 3
    MINIMIZE = 6
    RESTORE = 9
    SHOW = 5
    SHOWDEFAULT = 10
    SHOWMAXIMIZED = 3
    SHOWMINIMIZED = 2
    SHOWMINNOACTIVE = 7
    SHOWNA = 8
    SHOWNOACTIVATE = 4
    SHOWNORMAL = 1


class ERROR(enum.IntEnum):
    ZERO = 0
    FILE_NOT_FOUND = 2
    PATH_NOT_FOUND = 3
    BAD_FORMAT = 11
    ACCESS_DENIED = 5
    ASSOC_INCOMPLETE = 27
    DDE_BUSY = 30
    DDE_FAIL = 29
    DDE_TIMEOUT = 28
    DLL_NOT_FOUND = 32
    NO_ASSOC = 31
    OOM = 8
    SHARE = 26

def is_admin():
	return True
	try:
		return ctypes.windll.shell32.IsUserAnAdmin()
	except:
		return False

def run_as_admin(what):
	subprocess.Popen(what, stdout=subprocess.PIPE)

def set_ip(name,ip,mask='255.255.255.0',gw=None,dns='DHCP'):
	if ip == 'DHCP':
		run_as_admin('netsh interface ip set address "'+name+'" dhcp')
	else:
		if not gw:
			gw = ip[:ip.rfind('.')]+'.1'
		run_as_admin('netsh interface ip set address "'+name+'" static '+ip+' '+mask+' '+gw+' 1')

	if type(dns) == type("string"):
		run_as_admin('netsh interface ip add dns "'+name+'" '+dns)
	if type(dns) == type([]):
		run_as_admin('netsh interface ip add dns "'+name+'" '+dns[0])
		run_as_admin('netsh interface ip add dns "'+name+'" '+dns[0]+' index=2')

def get_conf():
	nic_list = {}
	p = subprocess.Popen('netsh interface ipv4 show config', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	name = 'Woot'
	check_dns = False
	for num, line in enumerate(p.stdout.readlines()):
		line = line.rstrip()
		if check_dns:
			if line.find(":") == -1:
				nic_list[name]['DNS'].append(line.lstrip())
			check_dns = False
		if line.startswith('Configuration for interface'):
			name = line[line.find('"'):-1]
			nic_list[name] = {"IP":None, "DHCP":None,"MASK":None,"Gateway":None,"DNS":[],"SUFFIX":None}
			continue
		if line.lstrip().startswith("DHCP enabled"):
			nic_list[name]['DHCP'] = line[line.find(":")+1:].lstrip()
			continue
		if line.lstrip().startswith("IP Address"):
			nic_list[name]['IP'] = line[line.find(":")+1:].lstrip()
			continue
		if line.lstrip().startswith("Subnet Prefix"):
			nic_list[name]['MASK'] = line[line.find("(mask")+6:-1].lstrip()
			continue
		if line.lstrip().startswith("DNS servers configured through DHCP") or line.lstrip().startswith("Statically Configured DNS Servers"):
			print "Name",name
			nic_list[name]['DNS'].append(line[line.find(":")+1:].lstrip())
			check_dns = True
			continue
		if line.lstrip().startswith("Register with which suffix"):
			nic_list[name]['SUFFIX'] = line[line.find(":")+1:].lstrip()
			continue
	return nic_list


def get_conf2():
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


def main():
	ip = "192.168.1.198"
	mask = "255.255.255.0"
	gateway = "192.168.1.1"
	dns = '8.8.8.8'

	set_ip("WiFi",ip, mask, gateway, dns)


def test():
	if is_admin():

		if True:
			nic_list = get_conf()

			import pprint
			pprint.pprint(nic_list)

			ip = "192.168.1.197"
			mask = "255.255.255.0"
			gateway = "192.168.1.1"
			dns = '8.8.8.8'

			#set_ip("WiFi",ip, mask, gateway, dns)
			set_ip("WiFi","DHCP")
			import time
			time.sleep(2)

			nic_list = get_conf()
			pprint.pprint(nic_list)
	else:
		ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

if __name__ == '__main__':
	#test()
	#get_conf()
	import pprint
	pprint.pprint(get_conf())
