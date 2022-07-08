import argparse
import socket
import sys
import textwrap
import pyfiglet
import threading
from time import time
from IPy import IP
from termcolor import colored


open_ports = []

def prep_args():
	parser = argparse.ArgumentParser(
		description="Python Based Port Scanner",
		usage="%(prog)s IP/Host",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=textwrap.dedent(''' Example:
		portscan.py  target #scans all the ports
		portscan.py  target -s <starting_port> -e <ending_port> #scans a range of ports
		portscan.py  target -s <starting_port> #scans from the given port to 65535th port
		portscan.py  target -e <ending_port> #scans from the 1st port to specidied port
		version enum
		single port
 	'''))
	parser.add_argument(metavar="Target",dest="ip",help="Target to scan")
	parser.add_argument("-s","--start",dest="start",metavar="",type=int,help="starting port",default=1)
	parser.add_argument("-e","--end",dest="end",metavar="",type=int,help="ending port",default=65535)
	parser.add_argument("-t","--threads",metavar="",dest="threads",type=int,help="threads to use", default=600)
	args = parser.parse_args()
	return args

def prep_ports(start, end):
	for port in range(start,end+1):
		yield port

def prep_threads(threads):
	thread_list = []
	for _ in range(threads+1):
		thread_list.append(threading.Thread(target=port_scan))

	for thread in thread_list:
		thread.start()

	for thread in thread_list:
		thread.join()

def port_scan():
	while True:
		try:
			s = socket.socket()
			s.settimeout(1)
			port = next(ports)
			s.connect((arguments.ip, port))
			open_ports.append(port)
		except (ConnectionRefusedError, socket.timeout):
			continue
		except StopIteration:
			break

if __name__ == "__main__":
	print(colored("""
  _____           _          _____                 
 |  __ \         | |        / ____|                
 | |__) |__  _ __| |_ _____| (___   ___ __ _ _ __  
 |  ___/ _ \| '__| __|______\___ \ / __/ _` | '_ \ 
 | |  | (_) | |  | |_       ____) | (_| (_| | | | |
 |_|   \___/|_|   \__|     |_____/ \___\__,_|_| |_|
""",'magenta'))

	arguments = prep_args()
	ports = prep_ports(arguments.start, arguments.end)
	start_time = time()
	prep_threads(arguments.threads)
	end_time = time()
	print("-"*50)
	print("\tOPEN PORTS    |    Service \t")
	print("-"*50+"\n")
	for single_port in open_ports:
		if single_port == 20:
			print("\t"+str(single_port)+"\r\r\t\t\tftp")
		elif single_port == 21:
			print("\t"+str(single_port)+"\r\t\t\t\tftp")
		elif single_port == 22:
			print("\t"+str(single_port)+"\r\t\t\t\tssh")
		elif single_port == 23:
			print("\t"+str(single_port)+"\r\t\t\t\telnet")
		elif single_port == 25:
			print("\t"+str(single_port)+"\r\t\t\t\tsmtp")
		elif single_port == 26:
			print("\t"+str(single_port)+"\r\t\t\t\trsftp")
		elif single_port == 53:
			print("\t"+str(single_port)+"\r\t\t\t\tdns")
		elif single_port == 67:
			print("\t"+str(single_port)+"\r\t\t\t\tdhcp")
		elif single_port == 68:
			print("\t"+str(single_port)+"\r\t\t\t\tdhcp")
		elif single_port == 69:
			print("\t"+str(single_port)+"\r\t\t\t\ttftp")
		elif single_port == 80:
			print("\t"+str(single_port)+"\r\t\t\t\thttp")
		elif single_port == 110:
			print("\t"+str(single_port)+"\r\t\t\t\tpop3")
		elif single_port == 111:
			print("\t"+str(single_port)+"\r\t\t\t\trpc")
		elif single_port == 119:
			print("\t"+str(single_port)+"\r\t\t\t\tnntp")
		elif single_port == 123:
			print("\t"+str(single_port)+"\r\t\t\t\tntp")
		elif single_port == 135:
			print("\t"+str(single_port)+"\r\t\t\t\tmsrpc")
		elif single_port == 139:
			print("\t"+str(single_port)+"\r\t\t\t\tsmb/samba or netbios-ssn")
		elif single_port == 143:
			print("\t"+str(single_port)+"\r\t\t\t\timap")
		elif single_port == 161:
			print("\t"+str(single_port)+"\r\t\t\t\tsnmp")
		elif single_port == 194:
			print("\t"+str(single_port)+"\r\t\t\t\tirc")
		elif single_port == 389:
			print("\t"+str(single_port)+"\r\t\t\t\tldap")
		elif single_port == 443:
			print("\t"+str(single_port)+"\r\t\t\t\thttps")
		elif single_port == 445:
			print("\t"+str(single_port)+"\r\t\t\t\tsmb/samba or microsoft-ds")
		elif single_port == 512:
			print("\t"+str(single_port)+"\r\t\t\t\texec")
		elif single_port == 513:
			print("\t"+str(single_port)+"\r\t\t\t\tlogin")
		elif single_port == 514:
			print("\t"+str(single_port)+"\r\t\t\t\tshell")
		elif single_port == 993:
			print("\t"+str(single_port)+"\r\t\t\t\timaps")
		elif single_port == 1099:
			print("\t"+str(single_port)+"\r\t\t\t\trmiregistry")
		elif single_port == 1524:
			print("\t"+str(single_port)+"\r\t\t\t\tingreslock")
		elif single_port == 1812:
			print("\t"+str(single_port)+"\r\t\t\t\tradius")
		elif single_port == 2049:
			print("\t"+str(single_port)+"\r\t\t\t\tnfs")
		elif single_port == 2121:
			print("\t"+str(single_port)+"\r\t\t\t\tccproxy-ftp")
		elif single_port == 3306:
			print("\t"+str(single_port)+"\r\t\t\t\tmysql")
		elif single_port == 3632:
			print("\t"+str(single_port)+"\r\t\t\t\tdistccd")
		elif single_port == 5432:
			print("\t"+str(single_port)+"\r\t\t\t\tpostgresql")
		elif single_port == 5900:
			print("\t"+str(single_port)+"\r\t\t\t\tvnc")
		elif single_port == 6000:
			print("\t"+str(single_port)+"\r\t\t\t\tx11")
		elif single_port == 6667:
			print("\t"+str(single_port)+"\r\t\t\t\tirc")
		elif single_port == 6697:
			print("\t"+str(single_port)+"\r\t\t\t\tircu-s")
		elif single_port == 7547:
			print("\t"+str(single_port)+"\r\t\t\t\tcwmp")
		elif single_port == 7547:
			print("\t"+str(single_port)+"\r\t\t\t\tcwmp")
		elif single_port == 8009:
			print("\t"+str(single_port)+"\r\t\t\t\tajp13")
		elif single_port == 8080:
			print("\t"+str(single_port)+"\r\t\t\t\thttp")
		elif single_port == 8787:
			print("\t"+str(single_port)+"\r\t\t\t\tmsgsrvr")
		elif single_port == 18182:
			print("\t"+str(single_port)+"\r\t\t\t\topsec-ufp")
		else:
			print("\t"+str(single_port)+"\r\t\t\t\tunassigned")
	print(f"\nTime taken - {round(end_time-start_time,2)}s")
