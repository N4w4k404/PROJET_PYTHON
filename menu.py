#!/usr/bin/env python
import os
import utils
import inquirer
import utils

def main() :
    i = 1
    # Show all interfacce
    print("\n")
    # Menu de choix 👌
    choices = ["Scanne les ports ouverts d'une machine cible",
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
    elif (choix == "EXIT"):
        print("-- Sortie du programme --")
        quit()
    else:
        print("Pas de choix?")

main()