#!/usr/bin/python
#####{INFO}################################################
#SCRIPT: Proxy-chk
#   JOB: Check Proxies IF A Proxy is available to work
#CodeBY: Muhammad Rafli
###########################################################
try:
	import requests,re,optparse,signal; from os import path
except ImportError:
	print("\n[!] Error: [Requests] Module Is Missed !!\n[!] Please Install It Use This Command: pip install requests")
	exit(1)

def handler(signum, frame):
    print("\n[!][CTRL+C]....Exiting!")
    exit(1)
signal.signal(signal.SIGINT, handler)

def isvalid(ip) : return True if re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip) else False
def cpro(proxy):
	proxies = {'http': proxy, 'https': proxy}
	try:
		resp = requests.get('https://www.wikipedia.org',proxies=proxies, timeout=5)
		proxip = resp.headers['X-Client-IP']
		if proxy.split(":")[0]==proxip: return True
		else : return False
	except Exception: return False

def avck(proxy, verb=None):
	if ":" not in proxy:
		if verb==False: return False
		print("\n[!] Invalid Proxy [{}] !!!".format(proxy))
		exit(1)
	ip,port = proxy.split(":")[0],proxy.split(":")[1]
	if isvalid(ip) !=True:
		if verb==False: return False
		print("\n[!] Invalid Proxy IP [{}] !!!".format(ip))
		exit(1)
	if not port.isdigit() or int(port) < 0 or int(port) > 65535:
		if verb==False: return False
		print("\n[!] Invalid Proxy Port[{}] !!!".format(port))
		exit(1)
def save(filename, value):
	if path.isfile(filename):
		outf = open(filename, 'a')
		outf.write(value)
		outf.close()
	else:
		outf = open(filename, 'w')
		outf.write(value)
		outf.close()

parse = optparse.OptionParser("""\033[1;38;5;208m
                         ____
                  /^\   / -- )
                 / | \ (____/
                / | | \ / /
               /_|_|_|_/ /
                |     / /
 __    __    __ |    / /__    __    __
[  ]__[  ]__[  ].   / /[  ]__[  ]__[  ]
|__            ____/ /___           __|
   |          / .------  )         |
   |         / /        /          |
   |        / /        /           |
~~~~~~~~~~~~-----------~~~~~~~~~~~~~~~~
    -={CODED BY : MUHAMMAD RAFLI}=-
     -={TEAM : Kalsel[E]Xploit}=-
    -={GREATZ TO : RCT AND 2E4H}=-
       -={PROXY-CHECKER-VALID}=-

USAGE: python2 proxy.py [OPTIONS...]
-------------
OPTIONS:
       |
    |--------
    |  -s --single [proxy_IP:proxy_port]     ::> Check Single Proxy
    |--------
    |  -m --many   [proxy,proxy2,etc]        ::> Check Many Proxy
    |--------
    |  -f --file   [file of proxies]         ::> Check All Proxies In File
    |--------
    |  -d --save   [file-name]               ::> Save The Good Proxies In Output-File
-------------
Examples:
        |
     |--------
     | python2 proxy.py -s 192.168.1.1:80
     |--------
     | python2 proxy.py -m 192.68.1.2:8080,192.68.1.2:53281,etc
     |--------
     | python2 proxy.py -f proxies.txt
     |--------
     | python2 proxy.py -f proxies.txt -d good-proxy.txt
     |--------
""")
def main():
	parse.add_option("-s",'-S','--single','--SINGLE', dest="Sproxy",type="string")
	parse.add_option("-m",'-M','--many','--MANY', dest="Mproxy",type="string")
	parse.add_option("-f",'-F','--file','--FILE', dest="Fproxy",type="string")
	parse.add_option("-d",'-D','--save','--SAVE', dest="save",type="string")
	(opt,args) = parse.parse_args()
	if opt.Sproxy !=None:
		proxy = opt.Sproxy
		avck(proxy)
		print("\n[~] Checking [ {} ]...".format(proxy))
		s = 0
		if cpro(proxy) == True:
			if opt.save !=None:
				fname = opt.save
				if not fname.endswith(".txt"): fname=fname+".txt"
				s = 1
				save(fname, "\n{}".format(proxy))
			print("[+] PROXY[ {} ] STATUS [ GOOD ]".format(proxy))
		else : print("\n[-] PROXY[ {} ] STATUS [ BAD! ]".format(proxy))
		if s == 1 : print("\n[*] Good Proxies Saved In [ {} ] ".format(fname))

	elif opt.Mproxy !=None:
		proxy = opt.Mproxy
		if "," not in proxy:
			print("\n[!] Error: Please Use [ , ] for Split the many proxies !!!")
			exit(1)
		proxies = proxy.split(",")
		s = 0
		if opt.save !=None:
			s = 1
			fname = opt.save
			if not fname.endswith(".txt"): fname=fname+".txt"
		for proxy in proxies:
			if not proxy.strip(): continue
			proxy = proxy.strip()
			if avck(proxy, verb=False) == False: print("[!] Invalid Proxy [ {} ] STATUS [ SKEEPD ]".format(proxy))
			elif cpro(proxy) == True:
				if s==1 : save(fname, "\n{}".format(proxy))
				print("[+] PROXY [ {} ] STATUS [ GOOD ]".format(proxy))
			else : print("[-] PROXY [ {} ] STATUS [ BAD! ]".format(proxy))
		if s == 1 : print("\n[*] Good Proxies Saved In [ {} ] ".format(fname))
	elif opt.Fproxy !=None:
		fproxy = opt.Fproxy
		try:
			fop = open(fproxy, 'r')
		except IOError:
			print("\n[!] Error: No Such File: {} !!!".format(fproxy))
			exit(1)
		s = 0
		if opt.save !=None:
			s = 1
			fname = opt.save
			if not fname.endswith(".txt"): fname=fname+".txt"
		for proxy in fop:
			if not proxy.strip(): continue
			proxy = proxy.strip()
			if avck(proxy, verb=False) == False : print("[!] Invalid Proxy [ {} ] STATUS [ SKEEPD ]".format(proxy))
			elif cpro(proxy) == True:
				if s == 1 : save(fname, "\n{}".format(proxy))
				print("[+] PROXY [ {} ] STATUS [ GOOD ]".format(proxy))
			else : print("[-] PROXY [ {} ] STATUS [ BAD! ]".format(proxy))
		if s == 1 : print("\n[*] Good Proxies Saved In [ {} ] ".format(fname))
		fop.close()
		
	else:
		print(parse.usage)
		exit(1)

if __name__ =='__main__':
	main()
##############################################################
#####################                #########################
#####################   END OF TOOL  #########################
#####################                #########################
##############################################################
#This Tool by Muhammad Rafli
#Have a nice day :)
#GoodBye
