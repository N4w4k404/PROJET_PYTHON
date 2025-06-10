#!/usr/bin/env python
# Ce fichier contiendra les fonctions appelées par menu.py
#!/usr/bin/env python
# Fonctionnne pour le 7 

# Socket librairie pour gérer l'interface réseau de bas niveau
import socket
# Librairie qui gère les processus
import psutil
# Librairie de implémentation de différent type de hashage
import hashlib
# Gestion des regex
import re

# Regex expression for validating IPv4
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

# Regex expression for validating IPv6
regex1 = "((([0-9a-fA-F]){1,4})\\:){7}"\
         "([0-9a-fA-F]){1,4}"

p = re.compile(regex)
p1 = re.compile(regex1)

def valid_ip(ip):

    # Regex de l'IPv4
    regex = ("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")

    # Regex de l'IPv6
    regex1 = ("((([0-9a-fA-F]){1,4})\\:){7}"\
            "([0-9a-fA-F]){1,4}")

    # regex IPV4
    p = re.compile(regex)
    # Regex IPV6
    p1 = re.compile(regex1)

    # Checking if it is a valid IPv4 addresses
    if (re.search(p, ip)):
        return ("Valid IPv4")

    # Checking if it is a valid IPv6 addresses
    elif (re.search(p1, ip)):
        return ("Valid IPv6")

    # Return Invalid
    return ("Invalid IP")

def scan_ports(target, start_port, end_port):
    # On vérifie la validité de l'IP
    v_ip = valid_ip(target)
    if (v_ip == "Invalid IP") :
        print(v_ip)
        quit()
    print(v_ip)
    print(f"Scan des ports ouverts sur {target}...")
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"Port {port} ouvert")
            s.close()
        except Exception as e:
            print(f"Erreur sur le port {port}: {e}")

