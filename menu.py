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
    choices = ["EXIT"]
    questions = [inquirer.List('choice', message="Que veux-tu faire ?", choices = choices)]
    answers = inquirer.prompt(questions)
    # Défini un variable avec le choix
    choix = answers["choice"]

    print (choix)
    if (choix == "EXIT"):
        print("-- Sortie du programme --")
        quit()
    else:
        print("Pas de choix?")

main()