#!/usr/bin/env python
import os
import sys
import utils
import inquirer
from fonction_identifie_vuln_web_courantes import identifievulnwebcourantes
from generate_report import generate_vulnerability_report
from chiffrement_Envoie_Ssh import secure_and_send_report
from datetime import datetime

# Obtenir le chemin absolu du répertoire courant
current_dir = os.path.dirname(os.path.abspath(__file__))
username_file = os.path.join(current_dir, "fonction_identifie_vuln_web_courantes", "usernames.txt")
password_file = os.path.join(current_dir, "fonction_identifie_vuln_web_courantes", "passwords.txt")
# base_url = "http://127.0.0.1:5000"

def main() :
    i = 1
    # Show all interfacce
    print("\n")
    # Menu de choix 👌
    choices = ["Scanne les ports ouverts d'une machine cible",
               "Identifie des vulnérabilités web courantes",
               "test automatiser",
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
        utils.scan_ports(ip,sport,eport)
    elif (choix == choices[1]):

        base_url=input("veuillez séléctionner une adresse ip :")

        urls = identifievulnwebcourantes.collect_urls(base_url)
        print("URLs collectées :", urls)
        XSS = identifievulnwebcourantes.xss(urls)
        SQL = identifievulnwebcourantes.sql(urls)
        BruteForce = identifievulnwebcourantes.bruteforce(username_file,password_file,urls)
   
        # Génération du rapport PDF
        rapport_file = os.path.join(current_dir, f"rapport_vulnerabilites_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        rapport_file = generate_vulnerability_report(XSS, SQL, BruteForce, rapport_file)
        print(f"\nRapport de vulnérabilités généré : {rapport_file}")
        
        # Sécurisation du rapport
        success, message = secure_and_send_report(rapport_file)
        print(message)

    elif (choix == choices[2]):

        ip = input("IP : ")
        sport = int(input ("\nStarting port : "))
        eport = int(input ("\nEnd ports : "))
        utils.scan_ports(ip,sport,eport)

        base_url=input("veuillez séléctionner une adresse ip :")
        urls = identifievulnwebcourantes.collect_urls(base_url)
        print("URLs collectées :", urls)
        XSS = identifievulnwebcourantes.xss(urls)
        SQL = identifievulnwebcourantes.sql(urls)
        BruteForce = identifievulnwebcourantes.bruteforce(username_file,password_file,urls)
        
        # Génération du rapport PDF
        rapport_file = os.path.join(current_dir, f"rapport_vulnerabilites_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        rapport_file = generate_vulnerability_report(XSS, SQL, BruteForce, rapport_file)
        print(f"\nRapport de vulnérabilités généré : {rapport_file}")
        
        # Sécurisation du rapport
        success, message = secure_and_send_report(rapport_file)
        print(message)

    elif (choix == "EXIT"):
        print("-- Sortie du programme --")
        quit()
    else:
        print("Pas de choix?")

if __name__ == "__main__":
    main()