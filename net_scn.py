# importing  library
import psutil;
import socket;
import ipaddress;
import pyfiglet;
from scapy.all import conf, ARP, srp, Ether;

#net scanner funky text
intro = pyfiglet.figlet_format("     .. NET SCANNER ..")
print(intro+"\n-------------------------------------------------------"+"\u00A9 Janidu Dilshan----------------------------------------------------")
#finding ip and subnet part I

def findIp():
    #identifying the connected network's route details
    route_details = conf.route.route("0.0.0.0")

    #actively connected host ip address
    host_ip = route_details[1]
    cidr=''
    #looping until matching connected host ip from available interfaces to take the subnetmask
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:  # Check only IPv4 addresses
                if host_ip == addr.address: #Check connected ip is matched
                    subnet_mask = addr.netmask
                    network = ipaddress.IPv4Network(f"{host_ip}/{subnet_mask}", strict=False)
                    cidr = str(network.prefixlen)
    return [host_ip,cidr]

#network scanning part II

target_net = '/'.join(findIp()) #formatting ip and subnet in cidr to parse furthur

arp = ARP(pdst = target_net) #creating arp packet
ether = Ether(dst ='ff:ff:ff:ff:ff:ff') #create ether broadcast message

packet = ether/arp #stacking both to one

result = srp(packet,timeout=4,verbose=0)[0] #capturing answered packets

targets =[] #list to store ips and macs in nework

for sent,recieved in result:
    targets.append({"ip":recieved.psrc,"mac":recieved.hwsrc}) #storing addresses in dictionary 

#visualizing addresses 
print("\n\n-------------------Network devices in this network---------------------\n")
print("IP addresse \t\t\tMAC addresse")
recordCounter= 0
for target in targets:
    print(f"{target['ip']}\t\t\t{target['mac']}")
    recordCounter +=1
print(f"\n{recordCounter} devices detected")






