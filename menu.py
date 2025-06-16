#!/usr/bin/env python
import os
import utils
import inquirer
import utils
from fonction_identifie_vuln_web_courantes import identifievulnwebcourantes

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
        urls = identifievulnwebcourantes.collect_urls(base_url)
        print("URLs collectées :", urls)
        identifievulnwebcourantes.xss(urls)
        identifievulnwebcourantes.sql(urls)
        identifievulnwebcourantes.bruteforce(username_file,password_file,urls)
    elif (choix == "EXIT"):
        print("-- Sortie du programme --")
        quit()
    else:
        print("Pas de choix?")

main()