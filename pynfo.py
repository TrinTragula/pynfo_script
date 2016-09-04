#!/usr/bin/env python
import requests
import socket
import whois
import GeoIP
import uuid

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

#get ip adress:
def get_ip():
	r = requests.get('http://httpbin.org/ip')
	if r.status_code == 200:
		ip = r.json()['origin']
	else:
		ip = "Connection error"
	return ip

def get_mac():
	raw_mac = '%012x'% uuid.getnode()
	macr = ""
	j=0
	for i in range(12):
		macr += str(raw_mac)[i]
		j+=1
		if j == 2:
			macr += ":"
			j=0
	return macr[:-1]

def geo_ip(ip):
	gi = GeoIP.open("GeoLiteCity.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)
	geo = gi.record_by_name(str(ip))
	return geo

def is_tor(ip):
	try:
		r = requests.get('https://check.torproject.org/exit-addresses', timeout=5)
		if str(ip) in r.text.replace("\n"," "):
			return True
		else:
			return False
	except:
		try:
			r = requests.get('https://www.dan.me.uk/torlist/', timeout=5)	
			if r.text == "Umm... You can only fetch the data every 30 minutes - sorry.  It's pointless any faster as I only update every 30 minutes anyway.\nIf you keep trying to download this list too often, you may get blocked from accessing it completely.\n(this is due to some people trying to download this list every minute!)":
				raise Exception('Asking too fast to dan.me.uk/torlist')
			if str(ip) in r.text.replace("\n"," "):
				return True
			else:
				return False
		except:
			print bcolors.WARNING + "[!] Unable to fetch tor exit nodes list."
			return False

def ip_score(ip):
	contact_email = "pynfoscript@gmail.com"
	r = requests.get("http://check.getipintel.net/check.php?ip="+str(ip)+"&contact=" + contact_email + "&format=json&flags=f") #&flags=f
	score = r.json()['result']
	return score

def main():
	print bcolors.OKBLUE + "!>" + bcolors.ENDC
	print bcolors.OKBLUE + "!> Pyinfo v-0.1 by TrinTragula (2016)" + bcolors.ENDC
	print bcolors.OKBLUE + "!> Please wait while we collect data.." + bcolors.ENDC
	print bcolors.OKBLUE + "!>" + bcolors.ENDC
	ip = get_ip()
	print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN + " IP:          " + bcolors.ENDC + ip 
	hostname = socket.gethostname()
	print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" Hostname:    "+ bcolors.ENDC + hostname
	mac = get_mac()
	print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" MAC address: "+ bcolors.ENDC + str(mac)
	who = socket.gethostbyaddr(str(ip))[0]
	print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" ISP:         "+ bcolors.ENDC + who
	geoip = geo_ip(ip)
	print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" Country:     "+ bcolors.ENDC + geoip["country_name"]
	tor = is_tor(ip)
	if tor == True:
		print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" Tor:         "+ bcolors.ENDC + "You are using Tor"
	else:
		print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" Tor:         "+ bcolors.ENDC + "You are " + bcolors.FAIL + "NOT"+  bcolors.ENDC + " using Tor"
	score = ip_score(ip)
	if float(score) > 0.75:
		print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" VPN/Proxy:   "+ bcolors.ENDC + "You are probably using a VPN/proxy"
	else:
		print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" VPN/Proxy:   "+ bcolors.ENDC + "You are probably" + bcolors.FAIL + " NOT"+  bcolors.ENDC + " using a VPN/proxy"
	print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +" Score:       "+ bcolors.ENDC + score
	print bcolors.OKBLUE + "!>" + bcolors.ENDC+ bcolors.OKGREEN +"              "+ bcolors.ENDC + "0-0.5 = Good IP | >0.5 = Bad IP | 1 = VPN or Proxy or Tor"
	print bcolors.OKBLUE + "!>" + bcolors.ENDC

if __name__ == "__main__":
    main()
