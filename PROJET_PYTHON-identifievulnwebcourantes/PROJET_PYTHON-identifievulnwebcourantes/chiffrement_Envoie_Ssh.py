from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import paramiko
import os
import json
from datetime import datetime
import glob

class SecurityManager:
    def __init__(self):
        # Création du dossier pour les clés s'il n'existe pas
        self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
        os.makedirs(self.keys_dir, exist_ok=True)
        
        # Génération des clés RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Sauvegarde des clés
        self._save_keys()

    def _save_keys(self):
        """Sauvegarde les clés RSA dans le dossier keys"""
        # Chemins des fichiers de clés
        private_key_path = os.path.join(self.keys_dir, "private_key.pem")
        public_key_path = os.path.join(self.keys_dir, "public_key.pem")
        
        # Sauvegarde de la clé privée
        with open(private_key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Sauvegarde de la clé publique
        with open(public_key_path, "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        print(f"✅ Clés RSA sauvegardées dans le dossier : {self.keys_dir}")

    def encrypt_file(self, file_path):
        """Chiffre un fichier avec AES"""
        # Génération d'une clé AES aléatoire
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        
        # Création du cipher AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Lecture et chiffrement du fichier
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Padding des données
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Chiffrement
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Création du fichier chiffré
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv)
            f.write(encrypted_data)
        
        print("✅ Fichier chiffré créé avec succès")
        
        return encrypted_file_path, aes_key

    def sign_file(self, file_path):
        """Signe un fichier avec la clé privée RSA"""
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Création de la signature
        signature = self.private_key.sign(
            file_data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Sauvegarde de la signature
        signature_file = file_path + '.sig'
        with open(signature_file, 'wb') as f:
            f.write(signature)
        
        return signature_file

    def send_file_ssh(self, file_path, hostname, username, password=None, key_path=None):
        """Envoie un fichier via SSH/SFTP"""
        try:
            # Création du client SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connexion au serveur
            if key_path:
                ssh.connect(hostname, username=username, key_filename=key_path)
            else:
                ssh.connect(hostname, username=username, password=password)
            
            # Création du client SFTP
            sftp = ssh.open_sftp()
            
            # Envoi du fichier
            remote_path = f"/home/{username}/rapports/{os.path.basename(file_path)}"
            sftp.put(file_path, remote_path)
            
            # Fermeture des connexions
            sftp.close()
            ssh.close()
            
            return True, f"Fichier envoyé avec succès vers {remote_path}"
            
        except Exception as e:
            return False, f"Erreur lors de l'envoi du fichier : {str(e)}"

def secure_report(report_path, hostname=None, username=None, password=None, key_path=None):
    """Fonction principale pour sécuriser et envoyer un rapport"""
    try:
        # Création du gestionnaire de sécurité
        security_manager = SecurityManager()
        
        # 1. Chiffrement du rapport
        encrypted_file, aes_key = security_manager.encrypt_file(report_path)
        print("✅ Rapport chiffré avec succès")
        
        # 2. Signature du fichier chiffré
        signature_file = security_manager.sign_file(encrypted_file)
        print("✅ Fichier chiffré signé avec succès")
        
        # Création du fichier de métadonnées
        metadata = {
            'timestamp': datetime.now().isoformat(),
            'original_file': os.path.basename(report_path),
            'encrypted_file': os.path.basename(encrypted_file),
            'signature_file': os.path.basename(signature_file),
            'aes_key': aes_key.hex()  # Conversion de la clé en hexadécimal pour le stockage
        }
        
        # Création du dossier pour les métadonnées s'il n'existe pas
        metadata_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metadata")
        os.makedirs(metadata_dir, exist_ok=True)
        
        metadata_file = os.path.join(metadata_dir, os.path.basename(report_path) + '.meta')
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)
        
        # Si les informations SSH sont fournies, on envoie les fichiers
        if hostname and username:
            # Envoi des fichiers via SSH
            success, message = security_manager.send_file_ssh(encrypted_file, hostname, username, password, key_path)
            if success:
                print("✅ Rapport envoyé avec succès")
                # Envoi de la signature
                security_manager.send_file_ssh(signature_file, hostname, username, password, key_path)
                # Envoi des métadonnées
                security_manager.send_file_ssh(metadata_file, hostname, username, password, key_path)
            else:
                print(f"❌ Erreur lors de l'envoi : {message}")
            return success, message
        else:
            print("ℹ️ Les fichiers ont été sécurisés localement")
            print(f"📁 Fichier chiffré : {encrypted_file}")
            print(f"📁 Fichier de signature : {signature_file}")
            print(f"📁 Fichier de métadonnées : {metadata_file}")
            return True, "Fichiers sécurisés localement"
        
    except Exception as e:
        return False, f"Erreur lors de la sécurisation du rapport : {str(e)}"

def secure_and_send_report(report_path):
    """Fonction simplifiée pour être appelée depuis menu.py"""
    print("\n🔒 Sécurisation du rapport...")
    return secure_report(report_path)

def list_pdf_files():
    """Liste tous les fichiers PDF disponibles dans le dossier courant."""
    pdf_files = glob.glob("*.pdf")
    if not pdf_files:
        print("❌ Aucun fichier PDF trouvé dans le répertoire courant.")
        return None
    print("\n📁 Fichiers PDF disponibles :")
    for i, file in enumerate(pdf_files, 1):
        print(f"{i}. {file}")
    while True:
        try:
            choice = input("\nChoisissez le numéro du fichier à sécuriser (0 pour quitter) : ").strip()
            if not choice:
                continue
            choice = int(choice)
            if choice == 0:
                return None
            if 1 <= choice <= len(pdf_files):
                return pdf_files[choice - 1]
            print("❌ Choix invalide. Veuillez réessayer.")
        except ValueError:
            print("❌ Veuillez entrer un numéro valide.")

if __name__ == "__main__":
    print("🔒 Programme de sécurisation de rapport PDF")
    print("=" * 50)
    while True:
        pdf_file = list_pdf_files()
        if pdf_file is None:
            break
        print(f"\n📄 Fichier sélectionné : {pdf_file}")
        try:
            manager = SecurityManager()
            manager.secure_report(pdf_file)
        except Exception as e:
            print(f"❌ Erreur lors de la sécurisation du rapport : {e}")
        choice = input("\nVoulez-vous sécuriser un autre fichier ? (o/n) : ").lower().strip()
        if choice != 'o':
            break
    print("\n👋 Au revoir !") 