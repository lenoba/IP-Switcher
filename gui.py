#!/usr/bin/env python
# -*- coding: utf-8 -*-

import Tkinter as tk
import os
from shutil import copy2
import subprocess
import traceback
import tkMessageBox
import sys

def run_as_admin(what):
	try:
		output = subprocess.check_output(what, stderr=subprocess.STDOUT, shell=False)
	except subprocess.CalledProcessError as exc:
		if exc.output.strip() == "DHCP is already enabled on this interface.":
			pass
		else:
			raise Exception(exc.output)

def set_ip(name,ip,mask='255.255.255.0',gw=None,dns='DHCP'):
	if ip == 'DHCP':
		run_as_admin('netsh interface ipv4 set address "'+name+'" dhcp')
	else:
		if not gw:
			gw = ip[:ip.rfind('.')]+'.1'
		run_as_admin('netsh interface ipv4 set address "'+name+'" static '+ip+' '+mask+' '+gw+' 1')

	if type(dns) == type("string"):
		if dns.upper() == "DHCP":
			run_as_admin('netsh interface ipv4 set dnsservers name="'+name+'" source=dhcp')
		else:
			run_as_admin('netsh interface ipv4 set dnsservers name="'+name+'" static '+dns+' primary')
	if type(dns) == type([]):
		run_as_admin('netsh interface ipv4 set dnsservers name="'+name+'" static '+dns[0]+' primary')
		run_as_admin('netsh interface ipv4 add dns name="'+name+'" addr='+dns[1]+' index=2')

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
			nic_list[name] = {"IP":"", "DHCP":"","MASK":"","Gateway":"","DNS":[],"SUFFIX":"", "DNSHDCP":False}
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
			if line.lstrip().startswith("DNS servers configured through DHCP"): nic_list[name]['DNSDHCP']=True
			else: nic_list[name]['DNSDHCP']=False
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

class StatusBar(tk.Frame):
	def __init__(self, master):
		tk.Frame.__init__(self, master)
		self.variable=tk.StringVar()
		self.label=tk.Label(self, bd=1, relief=tk.SUNKEN, anchor=tk.W,textvariable=self.variable, font=('arial',10,'normal'))
		self.variable.set('potato banana')
		self.label.pack(fill=tk.X)
		self.pack()
	def set(self, text):
		self.variable.set(text)

class App:

	def set_btn_pressed(self,btn,pressed=True):
		if pressed:
			btn.config(relief=tk.SUNKEN)
		else:
			btn.config(relief=tk.RAISED)

	def set_edit_text(self, edit, text):
		edit.delete(0,tk.END)
		if text:
			edit.insert(0,text)
		else:
			edit.insert(0,"")

	def __init__(self, master):
		column0_padx = 24
		row_pady = 36
		self.root = master

		self.mainFrame = tk.Frame(self.root)
		self.mainFrame.pack(fill=tk.BOTH)
		self.frameRow = []

		self.HW_NIC = []
		def_HW_NIC = None
		for key,value in get_conf().iteritems():
			self.HW_NIC.append(key)
			if value['IP'] not in ( "", "127.0.0.1" ):
				def_HW_NIC = key

		self.var_NIC = tk.StringVar(self.root)
		self.var_NIC.set(def_HW_NIC)

		_row = 0
		self.frameRow.append(tk.Frame(self.mainFrame))
		self.frameRow[_row].pack(fill=tk.BOTH)

		self.lbl_NIC = tk.Label(self.frameRow[_row], text="NIC: ")
		self.lbl_NIC.pack(side=tk.LEFT)
		self.list_NIC = tk.OptionMenu(self.frameRow[_row],self.var_NIC, *self.HW_NIC, command=self.on_list_NIC_change)
		self.list_NIC.pack(side=tk.LEFT, fill=tk.X, expand=tk.YES)

		_row += 1
		self.frameRow.append(tk.Frame(self.mainFrame))
		self.frameRow[_row].pack(fill=tk.BOTH, expand=tk.YES)

		self.var_radio_md = tk.StringVar()
		self.var_radio_md.set("M")
		self.radio_manual_dhcp1 = tk.Radiobutton(self.frameRow[_row], text="Manual", variable=self.var_radio_md, value="M",indicatoron=0, command=lambda : self.MD_change("M"))
		self.radio_manual_dhcp2 = tk.Radiobutton(self.frameRow[_row], text="DHCP", variable=self.var_radio_md, value="D",indicatoron=0, command=lambda : self.MD_change("D"))
		self.radio_manual_dhcp1.pack(side=tk.LEFT, fill=tk.X, expand=tk.YES)
		self.radio_manual_dhcp2.pack(side=tk.LEFT, fill=tk.X, expand=tk.YES)

		_row += 1
		self.frameRow.append(tk.Frame(self.mainFrame))
		self.frameRow[_row].pack(fill=tk.BOTH, expand=tk.YES)

		self.lbl_IP = tk.Label(self.frameRow[_row], text="IP: ")
		self.lbl_IP.grid(row=0,column=0)
		self.edit_IP = tk.Entry(self.frameRow[_row], width=40)
		self.edit_IP.grid(row=0,column=1)
		
		self.lbl_MASK = tk.Label(self.frameRow[_row], text="MASK: ")
		self.lbl_MASK.grid(row=1,column=0)
		self.edit_MASK = tk.Entry(self.frameRow[_row], width=40)
		self.edit_MASK.grid(row=1,column=1)

		self.lbl_GATEWAY = tk.Label(self.frameRow[_row], text="GATEWAY: ")
		self.lbl_GATEWAY.grid(row=2,column=0)
		self.edit_GATEWAY = tk.Entry(self.frameRow[_row], width=40)
		self.edit_GATEWAY.grid(row=2,column=1)

		self.lbl_DNS = tk.Label(self.frameRow[_row], text="DNS: ")
		self.lbl_DNS.grid(row=3,column=0)
		self.edit_DNS = tk.Entry(self.frameRow[_row], width=40)
		self.edit_DNS.grid(row=3,column=1)

		self.var_btn_DNS_state = False
		self.btn_DNS = tk.Button(self.frameRow[_row], text="DHCP", command=self.DnsDHCP)
		self.btn_DNS.grid(row=3, column=2)

		_row += 1
		self.frameRow.append(tk.Frame(self.mainFrame))
		self.frameRow[_row].pack(fill=tk.BOTH, expand=tk.YES)

		self.btn_makeData = tk.Button(self.frameRow[_row],text="Change IP", command=self.ChangeIP, padx=2)
		self.btn_makeData.pack(side=tk.LEFT)

		self.btn_ReleaseIP = tk.Button(self.frameRow[_row],text="Release IP", command=self.ReleaseIP, padx=2)
		self.btn_ReleaseIP.pack(side=tk.LEFT)

		self.btn_RenewIP = tk.Button(self.frameRow[_row],text="Renew IP", command=self.RenewIP, padx=2)
		self.btn_RenewIP.pack(side=tk.LEFT)

		self.btn_readData = tk.Button(self.frameRow[_row],text="Read settings", command=self.ReadData, padx=2)
		self.btn_readData.pack(side=tk.LEFT)

		self.btn_setDHCP = tk.Button(self.frameRow[_row],text="Set DHCP", command=self.SetDHCP, padx=2)
		self.btn_setDHCP.pack(side=tk.LEFT)

		_row += 1
		self.frameRow.append(tk.Frame(self.mainFrame))
		self.frameRow[_row].pack(fill=tk.BOTH, expand=tk.YES)
		self.statusBar = StatusBar(self.frameRow[_row])
		self.statusBar.pack(expand=tk.YES, fill=tk.BOTH)

		self.fill_current()

	def SetDHCP(self,*args,**kwards):
		try:
			set_ip(self.var_NIC.get(), "DHCP", dns="DHCP")
		except Exception as e:
			tkMessageBox.showerror("Setting IP failed", "\n".join(e))

	def DnsDHCP(self,*args,**kwards):
		if self.var_btn_DNS_state:
			#self.set_edit_text(self.edit_DNS, "8.8.8.8")
			self.var_btn_DNS_state = False
		else:
			self.set_edit_text(self.edit_DNS, "DHCP")
			self.var_btn_DNS_state = True
		self.set_btn_pressed(self.btn_DNS, self.var_btn_DNS_state)

	def MD_change(self, new):
		self.statusBar.set("Modifying settings...")

	def ReadData(self,*args,**kwards):
		self.fill_current()

	def on_list_NIC_change(self, *args,**kwards):
		self.set_edit_text(self.edit_IP, self.var_NIC.get())
		self.fill_current()

	def ChangeIP(self,*args,**kwards):
		self.statusBar.set("Applying settings...")
		_ip = self.edit_IP.get()
		_mask = self.edit_MASK.get()
		_gateway = self.edit_GATEWAY.get()
		_dns = self.edit_DNS.get()
		_dhcp = self.var_radio_md.get()
		_nic = self.var_NIC.get()

		if "," in _dns: _dns_list = _dns.split(",")
		else: 
			_dns_list = _dns
			if _dns_list.strip().upper() in ("", "DHCP" ) : _dns_list = "DHCP"

		try:
			if _dhcp == "D": set_ip(_nic, "DHCP", dns=_dns_list)
			else: set_ip(_nic, _ip,_mask, _gateway, dns=_dns_list)
		except Exception as e:
			tkMessageBox.showerror("Setting IP failed", "\n".join(e))

		self.mainFrame.after(3000,self.fill_current)

	def RenewIP(self, *args, **kwards):
		self.statusBar.set("Running 'ipconfig /renew' ...")
		run_as_admin("ipconfig /renew")
		self.mainFrame.after(3000, self.fill_current)

	def ReleaseIP(self, *args,**kwards):
		self.statusBar.set("Running 'ipconfig /release' ...")
		run_as_admin("ipconfig /release")
		self.mainFrame.after(3000, self.fill_current)

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
		self.set_btn_pressed(self.btn_DNS, current.get("DNSDHCP"))
		self.var_btn_DNS_state = current.get("DNSDHCP")
		self.statusBar.set("IP settings refreshed!")

def show_error(self, *args):
	err = traceback.format_exception(*args)
	tkMessageBox.showerror('Exception!',err)


def main():
	tk.Tk.report_callback_exception = show_error


	root = tk.Tk()
	root.title("IP Switcher")
	#root.minsize(800, 400)
	app = App(root)
	root.mainloop()

if __name__ == '__main__':
	main()