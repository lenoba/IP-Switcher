#!/usr/bin/env python
# -*- coding: utf-8 -*-

import Tkinter
import tkFileDialog
import os
from shutil import copy2
import subprocess


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
			name = line[line.find('"')+1:-1]
			nic_list[name] = {"IP":"", "DHCP":"","MASK":"","Gateway":"","DNS":[],"SUFFIX":""}
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
			nic_list[name]['DNS'].append(line[line.find(":")+1:].lstrip())
			check_dns = True
			continue
		if line.lstrip().startswith("Register with which suffix"):
			nic_list[name]['SUFFIX'] = line[line.find(":")+1:].lstrip()
			continue
		if line.lstrip().startswith("Default Gateway"):
			nic_list[name]['Gateway'] = line[line.find(":")+1:].lstrip()
			continue
	return nic_list




class App:

	def set_edit_text(self, edit, text):
		edit.delete(0,Tkinter.END)
		if text:
			edit.insert(0,text)
		else:
			edit.insert(0,"")

	def __init__(self, master):
		column0_padx = 24
		row_pady = 36
		self.root = master

		self.HW_NIC = []
		def_HW_NIC = None
		for key,value in get_conf().iteritems():
			self.HW_NIC.append(key)
			if value['IP'] not in ( "", "127.0.0.1" ):
				def_HW_NIC = key

		self.var_NIC = Tkinter.StringVar(self.root)
		self.var_NIC.set(def_HW_NIC)

		_row = 0
		self.lbl_NIC = Tkinter.Label(master, text="NIC: ")
		self.lbl_NIC.grid(row=_row,column=0)
		self.list_NIC = Tkinter.OptionMenu(master,self.var_NIC, *self.HW_NIC, command=self.on_list_NIC_change)
		self.list_NIC.grid(row=_row,column=1)

		_row += 1
		self.var_radio_md = Tkinter.StringVar()
		self.var_radio_md.set("M")
		self.radio_manual_dhcp1 = Tkinter.Radiobutton(master, text="Manual", variable=self.var_radio_md, value="M",indicatoron=0)
		self.radio_manual_dhcp2 = Tkinter.Radiobutton(master, text="DHCP", variable=self.var_radio_md, value="D",indicatoron=0)
		self.radio_manual_dhcp1.grid(row=_row,column=0)
		self.radio_manual_dhcp2.grid(row=_row,column=1)

		_row += 1
		self.lbl_IP = Tkinter.Label(master, text="IP: ")
		self.lbl_IP.grid(row=_row,column=0)
		self.edit_IP = Tkinter.Entry(master, width=40)
		self.edit_IP.grid(row=_row,column=1)

		_row += 1
		self.lbl_MASK = Tkinter.Label(master, text="MASK: ")
		self.lbl_MASK.grid(row=_row,column=0)
		self.edit_MASK = Tkinter.Entry(master, width=40)
		self.edit_MASK.grid(row=_row,column=1)

		_row += 1
		self.lbl_GATEWAY = Tkinter.Label(master, text="GATEAY: ")
		self.lbl_GATEWAY.grid(row=_row,column=0)
		self.edit_GATEWAY = Tkinter.Entry(master, width=40)
		self.edit_GATEWAY.grid(row=_row,column=1)

		_row += 1
		self.lbl_DNS = Tkinter.Label(master, text="DNS: ")
		self.lbl_DNS.grid(row=_row,column=0)
		self.edit_DNS = Tkinter.Entry(master, width=40)
		self.edit_DNS.grid(row=_row,column=1)

		_row += 1
		self.btn_makeData = Tkinter.Button(text="Change IP", command=self.ChangeIP, padx=2)
		self.btn_makeData.grid(row=_row,column=0)

		self.btn_ReleaseIP = Tkinter.Button(text="Release IP", command=self.ReleaseIP, padx=2)
		self.btn_ReleaseIP.grid(row=_row,column=1)

		self.btn_RenewIP = Tkinter.Button(text="Renew IP", command=self.RenewIP, padx=2)
		self.btn_RenewIP.grid(row=_row,column=2)

		self.fill_current()

	def on_list_NIC_change(self, *args,**kwards):
		self.set_edit_text(self.edit_IP, self.var_NIC.get())
		self.fill_current()

	def ChangeIP(self,*args,**kwards):
		pass

	def RenewIP(self, *args, **kwards):
		pass

	def ReleaseIP(self, *args,**kwards):
		pass

	def fill_current(self, NIC=None):
		conf = get_conf()
		if NIC in conf:
			current = conf[NIC]
		else:
			current = conf[self.var_NIC.get()]

		self.set_edit_text(self.edit_IP, current.get("IP","0.0.0.0"))
		self.set_edit_text(self.edit_MASK, current.get("MASK","0.0.0.0"))
		self.set_edit_text(self.edit_GATEWAY, current.get("Gateway","0.0.0.0"))
		dns = ", ".join(current.get("DNS",None))
		if dns != "None":
			self.set_edit_text(self.edit_DNS, dns)
		else: 
			self.set_edit_text(self.edit_DNS, "")
		self.var_radio_md.set("D" if current.get("DHCP") == "Yes" else "M")



root = Tkinter.Tk()
root.title("IP Switcher")
#root.minsize(800, 400)
app = App(root)
root.mainloop()