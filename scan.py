from pystyle import Colors, Colorate
import nmap3
from treelib import Node, Tree

import time
import sys
import os

def loading_animation():
	animation = ["   ", ".  ", ".. ", "..."]
	for _ in range(10):
		for frame in animation:
			sys.stdout.write("\rDémarrage en cours de phlaris" + frame)
			sys.stdout.flush()
			time.sleep(0.3)
	os.system("clear")

#loading_animation()

nmap = nmap3.Nmap()

tree = Tree()

title="""

      :::::::::  :::    ::: :::            :::     :::::::::  ::::::::::: :::::::: 
     :+:    :+: :+:    :+: :+:          :+: :+:   :+:    :+:     :+:    :+:    :+: 
    +:+    +:+ +:+    +:+ +:+         +:+   +:+  +:+    +:+     +:+    +:+         
   +#++:++#+  +#++:++#++ +#+        +#++:++#++: +#++:++#:      +#+    +#++:++#++   
  +#+        +#+    +#+ +#+        +#+     +#+ +#+    +#+     +#+           +#+    
 #+#        #+#    #+# #+#        #+#     #+# #+#    #+#     #+#    #+#    #+#     
###        ###    ### ########## ###     ### ###    ### ########### ########      
"""

print(Colorate.Horizontal(Colors.blue_to_white, title), "\n")
host = input("Host $: ")
tree.create_node(host, 0)

def __categories(cat:str=None, id:int=None, nt:int=None, state:str=None):
	#dict = []
	#dict.append({cat: [{'ID':id, 'Nombre total':nt, 'Class':state}]})
	#for element in dict:
	#	print(element[cat][0]['ID'])
	tree.create_node(cat, id, parent=0)

def _phlaris_SC_port(url:str):
	results = nmap.scan_top_ports(url)
	__categories("Port Vulnérable", 1, 1, "important")
	ipAddress = list(results.keys())[0]
	for data in results[ipAddress]['ports']:
		if data['state'] == 'open':
			tree.create_node('Port: [{}]'.format(data['portid']), data['portid'], parent=1)
			tree.create_node('Protocol : {}'.format(data['protocol']),parent=data['portid'])
			tree.create_node('Reason : {}'.format(data['reason']), parent=data['portid'])
			tree.create_node('Service name : {}'.format(data['service']['name']), parent=data['portid'])
			tree.create_node('Confidence : {}'.format(data['service']['conf']), parent=data['portid'])


def _phlaris_DNS_nse(url:str):
	results = nmap.nmap_dns_brute_script(url)
	__categories("Vulnérabilité DNS", 2, 1, "important")
	#print("Vulnérabilité DNS: ")
	for key in range(len(results)):
		#print('Hostname => ',results[key]['hostname'], "| Adresse IP => ", results[key]['address'])
		tree.create_node('{} | {}'.format(results[key]['hostname'], results[key]['address']), parent=2)

_phlaris_SC_port(host), _phlaris_DNS_nse(host)
tree.show()
