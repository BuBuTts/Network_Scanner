# importing  library
import psutil;
import socket;
import ipaddress;
import pyfiglet;
import requests;
import time;
import csv;
from scapy.all import conf, ARP, srp, Ether;

#net scanner funky text
intro = pyfiglet.figlet_format("      NET SCANNER")
print(intro+"\n-------------------------------------------------------"+"\u00A9 Janidu Dilshan----------------------------------------------------")
#finding ip and subnet part I



#Finding ip and subnet
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



#finding vendor using MAC
def findVendor_Api(mac_address):

    #requset part
    url = "https://mac-address-lookup1.p.rapidapi.com/static_rapid/mac_lookup/"
    querystring = {"query":mac_address}
    headers = {
	    "x-rapidapi-key": "d0a34b129cmshec73ae27dfc2bd9p147508jsnfba5d815ca8e",
	    "x-rapidapi-host": "mac-address-lookup1.p.rapidapi.com"
    }
    respone = requests.get(url,headers=headers,params=querystring)

    #delyaing time since free API version don't allow more than one in 1sec
    time.sleep(1.2)
    #response handling
    if respone.status_code == 200:
        result = respone.json()
        if result['errors'] != []:
            vendor = result['errors']
        else:
            vendor = result['result'][0]['name']
    else:
        vendor = f"request failed : status code:{respone.status_code}"

    vendorDetail = str(vendor)

    return vendorDetail



#load dataset to dictionary (one time)
def load_mac_dict(datafile = "mac-vendors-export.csv"):
    mac_dict = {}
    with open(datafile,mode="r",encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if row: #ensuring row isnt empty
                mac_dict[row[0].upper()] = row[1]
    return mac_dict


#find vendor using mac_dict dictionary
def findVendor_file(macAddr,loaded_mac):
    mac_key = macAddr.upper()[:8]
    return loaded_mac.get(mac_key, "\033[31mVendor detail unknown try online mode\033[0m")


#laoding mac dictionary
loaded_mac_dict = load_mac_dict()


#printing result on console
def print_result():
    print("\n\n-------------------Network devices in this network---------------------\n")
    print("IP addresse \t\t\tMAC addresse\t\t\tvendor")
    recordCounter= 0
    for target in targets:
        print(f"{target['ip']}\t\t\t{target['mac']}\t{target['vendor']}")
        recordCounter +=1
    print(f"\n{recordCounter} devices detected")
    return




#network scanning part II

target_net = '/'.join(findIp()) #formatting ip and subnet in cidr to parse 

arp = ARP(pdst = target_net) #creating arp packet
ether = Ether(dst ='ff:ff:ff:ff:ff:ff') #create ether broadcast message

packet = ether/arp #stacking both to one

result = srp(packet,timeout=5,verbose=0)[0] #capturing answered packets







#looping for user interactiveness
while(True):
    targets =[] #list to store ips and macs in nework

#Letting user to decide to either do mac address lookup along with the scan
    print("Both scans give you the list of ip addresse,mac addresse and vendor of each device in network.\nWhile fast scan give you the vendor's name associated with the mac addresses reading localy available dataset(\033[31mdataset file has to be in the same directory\033[0m]),\nAdvance scan use address lookup API (more updated details).\n!\033[31mCaution : advance network may require longer time due to API service restricted one request for 1 second\033[0m .")
    print("1. Fast network scan\n2. Advanced network scan\n3. \033[31mExit\033[0m")
    answer = int(input("Enter option number : "))



#fast scanning mode (local search for vendor)

    if answer == 1: #fast scanning
        print("\nfast Scanning...")
        print("reading dataset...")
        for sent,recieved in result:
            targets.append({"ip":recieved.psrc,"mac":recieved.hwsrc,"vendor":findVendor_file(recieved.hwsrc,loaded_mac_dict)}) #storing addresses in dictionary 

#visualizing addresses 
        print_result()








#advance scanning mode (vendor search through address lookup API)

    elif answer == 2: #Advance scanning
        print("\nadvanced Scanning...this will take time don't panic")
        for sent,recieved in result:
            targets.append({"ip":recieved.psrc,"mac":recieved.hwsrc,"vendor":findVendor_Api(recieved.hwsrc)})
    
        print_result()

    elif answer ==3:
        print("Until next time...")
        time.sleep(0.5)
        break

    else:
        continue
    








