#!/usr/bin/env python
from scapy.all import *
import inquirer
# Ajouter les commande os
import os
# Importer la librairie qui affiche la structure des fichiers
from directory_tree import DisplayTree
# Envoi des requêtes (sera utiliser pour https://www.abuseipdb.com
import requests
import json

# Utilisation d'un dictionnaire en variable globale afin de écupérer les IPs problématiques
IPs={}

def ip_abuse(ip):
    APIKEY = "f720efa2b1afbcbf346dd786b8982bdb0ff0c22f596658640055d83bc2bcede1d501ae5d48857e5e"
    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': APIKEY
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    # Formatted output
    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))


# ============= Fonctions visant à afficher le contenu des requêtes durant la capture =============

# Fonction pour afficher les requêtes DNS lisiblement
def afficher_dns(dns_packet) :
    datas = {}
    print(dns_packet)
    try :
        # Récupère les informations du DNS (les noms de domaine demandés)
        if dns_packet.qd:  # Si il y a des questions DNS
            for question in dns_packet.qd:
                datas["Requête DNS"] = question.qname.decode()
                return(datas)
        else:
            print("Pas de requête DNS dans ce paquet.")
            datas["Requête DNS"] = "Pas de requête DNS dans ce paquet."
            return(datas)
    except Exception as e :
        print(f"[ERREUR DNS] - Impossible de traiter la requête DNS : {e}")


# Fonction pour obtenir un nom lisible du protocole à partir du numéro du protocole 
def get_protocole_nom(proto_num) :
    # Dictionnaire des protocoles communs en fonction du numéro
    protocole_dict = {
       1: "ICMP",
       6: "TCP",
       17: "UDP",
    }
    return protocole_dict.get(proto_num, f"Protocole {proto_num} inconnu")

"""
Fonction qui vise à afficher les paquets au fur et à mesure des captures
"""
def afficher_pkt(packets) :
    datas = {}
    raw_data = bytes(packets.payload)
    raw = ''
    try:
        for pkt in packets:
            # Vérifie si le pkt a des informations IP
            # Si le pkt contient des données brutes (Raw)
            if raw_data:
                raw = "contenant de la donnée"
                data = pkt[Raw].load
                hexdump(pkt)
            if ARP in pkt:
                print("\n------------------------ Paquet ARP {raw} capturé ------------------------")
                print("ARP From:", pkt[ARP].psrc, "to", pkt[ARP].pdst)
                mac_src = pkt[ARP].hwsrc
                print("MAC ADRESS SOURCE = ",mac_src)
                mac_dst = pkt[ARP].hwdst
                summary = pkt[ARP].summary()
                datas["ARP - MAC Source"] = str(mac_src)
                datas["ARP - MAC Dest"] = str(mac_dst)
                datas["ARP - Summary"] = str(summary)
            if IP in pkt:
                print(f"\n------------------------ Paquet IP {raw} capturé ------------------------")
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                protocole = pkt[IP].proto
                protocole = get_protocole_nom(protocole)
                taille = pkt[IP].len
                packets_counter(pkt)
                datas["IP Source"] = ip_src
                print("IP Source : ",ip_src)
                datas["IP Destination"] = ip_dst
                print("IP Destination : ",ip_dst)
                datas["Protocole"] = protocole
                print("Protocole : ",protocole)
                datas["Taille"] = taille
                print("Taille : ",taille)
                if TCP in pkt:
                    datas["Contenu TCP"] = data
                    print("Port source :", pkt[TCP].sport)
                    print("Port destination :", pkt[TCP].dport)
                    print("Flags TCP :", pkt[TCP].flags)
                if UDP in pkt:
                    datas["Contenu UDP"] = data
                    print("Port source :", pkt[UDP].sport)
                    print("Port destination :", pkt[UDP].dport)
            if DNS in pkt:
                afficher_dns(pkt)
#        detect_syn_flood(pkt)
#        detect_malicious_payload(pkt)
#        print("---------------------------------------------------------------\n")     
        return (datas)

    except Exception as e :
        print(f"[ERREUR] - Impossible de traiter le paquet : {e}")

# ============= Capture des paquets =============

"""
Ici on va capturer tous les paquest quelque soit l'interface réseau
"""
def capture_all(cnt,file):
    try :
        # Affiche les interfaces réseau disponibles
        show_interfaces()
        interface = input("\nChoisi ton interface réseau : ")
        # Capture des paquets avec un format lisible
        print("\nDébut de la capture...")
        capture = sniff(iface=interface, timeout=cnt,prn=lambda x: afficher_pkt(x) )
    except ValueError :
        print("[ERREUR] - Valeur incorrecte. Assurez-vous de saisir un nombre pour la quantité de paquets.")
    except Exception as e :
        print(f"[ERREUR] - Une erreur est survenue: {e}")
    finally :
        wrpcap(file,capture)
        print("\nLecture du pcap...")
        return capture

# ============= Compte les paquets =============
def packets_counter (pkt) :
    global IPs
    try :
        # Liste de IPs rencontrées et du nombre de requêtes envoyées par ces IPs
        """
        Objectif de notre tableau IPs : Rassembler les IPs recontrées avec le nombre de fois où elles l'ont été
        """
        found = False
        # IPs source du packet
        # compteur global pour enregistrer le nombre de requêtes
        if IP in pkt:
            pkt_src = pkt[IP].src
            # IPs cible
            pkt_dst = pkt[IP].dst
            # Comptage des requêtes par IP source
            if pkt_src in IPs:
                IPs[pkt_src] = int(IPs[pkt_src] + 1)
            else :
                IPs[pkt_src] = int(1)
        # Si l'IP n'est pas trouvée, on l'ajoute
        else:
            print("[INFO] - Paquet sans couche IP")
            return ("Paquet sans couche IP")
        # print("NUMBER OF ", pkt_src , " = " ,IPs[pkt_src])
    except Exception as e:
        print(f"[ERROR] - Problème lors du traitement du paquet : {e}")

# ============= Détection des anomalies =============

"""
Check les IPs et vérifie si elles flood 
"""
def check_ip(cnt) :
    # tant que j'ai des clefs IPs dans 
    global IPs
    ip_flooding = {}
    for key, val in IPs.items() : 
        # Si en moyenne plus de 20 requêtes par secondes sont envoyées on retourne le résultat
        if val >= (cnt * 20) :
            # Key = IP - Val = nombre de requêtes
            # Ajout de l'ip flooder dans notre tableau
            ip_flooding[key] = val
            print(f"{key} IP IS FLOODING with {val} requests")
            #print("[ WARNING ] - IP ", key, " a fait ", val, " requêtes!")
    print(IPs)
    return(ip_flooding)

"""
Lit les paquets précédemment enregistrés dans le fichier pcap et détecte les anomalies
"""
def packets_reader(file):
    packets = rdpcap(file)
    for pkt in packets:
        if (pkt.haslayer(TCP) and pkt[TCP].flags == "S" and pkt[TCP].dport > 10):
            print(f"Paquet suspect : {pkt.summary()}")

def detect_syn_flood(packets): 
    syn_count = 0 
    for pkt in packets: 
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S": 
            syn_count += 1 
    print(f"Nombre de SYN détectés : {syn_count}")
    return(syn_count)

def detect_arp_spoofing(packets): 
    # crée ma bbliothèque ARP 
    arp_table = {} 
    # tant qu'il y a des paquets on continue
    for pkt in packets: 
        # Si
        if pkt.haslayer(ARP) and pkt[ARP].op == 2: # Réponse ARP 
            ip = pkt[ARP].psrc 
            mac = pkt[ARP].hwsrc 
            if ip in arp_table and arp_table[ip] != mac: 
                datas[ip] = mac
                return (1,datas)
            else: 
                arp_table[ip] = mac 
                return (0,arp_table[ip])
    return(0)

def detect_malicious_payload(packets): 
    malicious_payloads = {}
    for pkt in packets:
        if pkt.haslayer(Raw) and b"malicious" in pkt[Raw].load: 
            malicious_payloads[pkt[IP].src] = pkt[Raw].load
            print(f"Malicious payload is from = ",malicious_payloads)
            return malicious_payloads

# Fonction principale
"""
Cette fonction a pour objectif de checker les différentes requêtes anormales telles que :
    - Check des SYN flood

Elle commence par définir le fichier d'enregistrement au format pcap afin de pouvoir le lire avec Wireshark
Ensuite, elle définie le temp pendant lequel le réseau choisi sera analysé
Ajoute les informations lié

"""
def check_warning() :
    # Affiche l'arborescence
    requests = 0
    nbr = 0
    print("\nVos fichiers : ",os.listdir())
    print("\n")
    file = input("Nom du fichier à exporter : ")
    file = file + ".pcap"
    cnt = int(input("Temps de capture en secondes : "))
    # Import du dictionnaire IP afin de 
    global IPs
    # Capture toutes les requêtes
    capture_all(cnt,file)
    # Exporte la capture dans un fichier pcap
    packet = rdpcap(file)
    print(f"\n----------------------- Détection détection de syn flood")
    # Check le nombre de fois ou une IP apparait
    print("CHECK_IP : ",check_ip(cnt))
    # Détecte les potentiel flood de requête syn
    print("DETECT SYN FLOOD : ",detect_syn_flood(packet))
    # Détecte les arp spoofing
    print(f"\n----------------------- Détection d'arp spoofing")
    print("DETECT ARP SPOOFING", detect_arp_spoofing(packet))

    print(f"\n----------------------- Détection de présences malveillante dans les packet")
    # Lit les paquets et détecte 'malicious'
    print("DETECT MALICIOUS PAYLOAD :", detect_malicious_payload(packet))

    print(f"\nVoici les IPs recontrées et leurs nombre de requêtes en {cnt} secondes\n")
    for key,val in IPs.items() :
        print(f"L'IP {key} a envoyé {val} requêtes")
        #ip_abuse(key)
        requests += val
        nbr += 1
    print(f"\nUn total de {requests} requêtes a été envoyé pour un total de {nbr} IP")

