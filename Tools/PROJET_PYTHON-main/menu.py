#!/usr/bin/env python
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import chiffrement_Ssh
import utils
import inquirer
import utils
from tools import anom_detect
from fonction_identifie_vuln_web_courantes import identifievulnwebcourantes
from generate_report import generate_vulnerability_report, generate_network_report, generate_port_scan_report
from chiffrement_Ssh import main

username_file = "fonction_identifie_vuln_web_courantes/usernames.txt"
password_file = "fonction_identifie_vuln_web_courantes/passwords.txt"
base_url = "http://127.0.0.1:5000"

def main() :
    i = 1
    # Show all interfacce
    print("\n")
    # Menu de choix 👌
    choices = ["Scanne les ports ouverts d'une machine cible",
               "Identifie des vulnérabilités web courantes",
               "enregistre les captures réseaux et lance une détection",
               "EXIT"]
    questions = [inquirer.List('choice', message="Que veux-tu faire ?", choices = choices)]
    answers = inquirer.prompt(questions)
    # Défini un variable avec le choix
    choix = answers["choice"]

    print (choix)
    if (choix == choices[0]):
        ip = input("IP : ")
        sport = int(input ("\nStarting port : "))
        eport = int(input ("\nEnd ports : "))
        resultat = utils.scan_ports(ip,sport,eport)
          # Génération du rapport
        generate_port_scan_report(resultat, ip, sport, eport)
        print("Rapport généré : rapport_scan_ports.pdf")
        chiffrement_Ssh.main()
        
    elif (choix == choices[1]):
        urls = identifievulnwebcourantes.collect_urls(base_url)
        print("URLs collectées :", urls)
        xss_results = identifievulnwebcourantes.xss(urls)
        sql_results = identifievulnwebcourantes.sql(urls)
        bruteforce_results = identifievulnwebcourantes.bruteforce(username_file,password_file,urls)
        generate_vulnerability_report(xss_results, sql_results, bruteforce_results)
        print("Rapport généré : rapport_vulnerabilites.pdf")
        chiffrement_Ssh.main()
    elif (choix == choices[2]):
        res_anom_detect = anom_detect.check_warning()
        # Generation de rapport 
        generate_network_report(res_anom_detect)
        print(f'Reseaux = {res_anom_detect}')
        print("Rapport généré : rapport_reseau.pdf")
        chiffrement_Ssh.main()
        print(f'Resultat : {res_anom_detect}')
    elif (choix == "EXIT"):
        print("-- Sortie du programme --")
        quit()
    else:
        print("Pas de choix?")

main()
