#!/usr/bin/env python
from scapy.all import *
import utils
import inquirer

def main() :
    i = 1
    # Show all interfacce
    print("\n")
    # Menu de choix 👌
    choices = ["1. Lecteur de paquets",
               "2. Packets sender",
               "3. SYN flood",
               "4. ARP Spoof",
               "EXIT"]
    questions = [inquirer.List('choice', message="Que veux-tu faire ?", choices = choices)]
    answers = inquirer.prompt(questions)
    # Défini un variable avec le choix
    choix = answers["choice"]

    print (choix)
    if (choix == choices[0]):
        # 1. Envoyer des paquets simple
        utils.packets_reader() 
    elif (choix == choices[1]):
        # Adresse IP du serveur local et du port cible
        dst_ip = input("Ip de destination: ")
        dst_port = int(input("Port de destination: "))
        src_port = int(input("Port de la source: "))
        loop = int(input("Combien de fois : "))
        data = input("Data: ")
        cnt = int(input("Combien de paquets à la fois : "))
        while i < loop:
            utils.packet_sender(dst_ip,dst_port,src_port,data,cnt)
            i += 1
        # 1. Envoyer des paquets simple
        utils.packets_reader() 
    elif (choix == choices[2]):
        dst_ip = input("Ip de destination: ")
        dst_port = int(input("Port de destination: "))
        pkt_nbr = int(input("Nombre de paquets: "))
        pkt_size = int(input("Taille de paquets: "))
        utils.send_syn(dst_ip, dst_port, pkt_nbr, pkt_size)
    elif (choix == choices[3]) :
        utils.arp_spoof()
    elif (choix == "EXIT"):
        print("-- Sortie du programme --")
        quit()
    else:
        print("Pas de choix?")

main()

