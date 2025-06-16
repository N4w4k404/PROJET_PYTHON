from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import json
import glob

class SecurityVerifier:
    def __init__(self):
        # Définition du répertoire de base
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Recherche du dossier des clés
        self.keys_dir = self._find_keys_directory()
        if not self.keys_dir:
            raise FileNotFoundError("❌ Dossier des clés non trouvé")
        
        # Chargement de la clé publique
        self.public_key = self._load_public_key()

    def _find_keys_directory(self):
        """Recherche le dossier des clés dans le répertoire courant et ses sous-répertoires"""
        # Liste des dossiers possibles pour les clés
        possible_dirs = [
            "keys",
            "key",
            "clefs",
            "clef",
            "certificates",
            "certificats"
        ]
        
        # Recherche dans le répertoire de base
        for dir_name in possible_dirs:
            dir_path = os.path.join(self.base_dir, dir_name)
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                return dir_path
        
        # Recherche dans les sous-répertoires
        for root, dirs, files in os.walk(self.base_dir):
            for dir_name in possible_dirs:
                if dir_name in dirs:
                    return os.path.abspath(os.path.join(root, dir_name))
        
        return None

    def _load_public_key(self):
        """Charge la clé publique depuis le dossier des clés"""
        # Liste des extensions possibles pour les clés publiques
        key_extensions = [".pem", ".pub", ".key", ".crt"]
        
        # Recherche de la clé publique
        for ext in key_extensions:
            key_files = glob.glob(os.path.join(self.keys_dir, f"*{ext}"))
            for key_file in key_files:
                try:
                    with open(key_file, "rb") as f:
                        return serialization.load_pem_public_key(
                            f.read(),
                            backend=default_backend()
                        )
                except:
                    continue
        
        raise FileNotFoundError("❌ Clé publique non trouvée")

    def _find_associated_files(self, encrypted_file_path):
        """Trouve les fichiers associés (signature et métadonnées)"""
        base_name = os.path.splitext(encrypted_file_path)[0]
        signature_path = None
        metadata_path = None
        
        # Recherche du fichier de signature
        signature_patterns = [
            f"{base_name}.sig",
            f"{base_name}.sign",
            f"{base_name}.signature"
        ]
        for pattern in signature_patterns:
            if os.path.exists(pattern):
                signature_path = pattern
                break
        
        # Recherche du fichier de métadonnées
        metadata_patterns = [
            f"{base_name}.meta",
            f"{base_name}.json",
            f"{base_name}.info"
        ]
        
        # Recherche dans le répertoire courant
        for pattern in metadata_patterns:
            if os.path.exists(pattern):
                metadata_path = pattern
                break
        
        # Si non trouvé, recherche dans le dossier metadata
        if not metadata_path:
            metadata_dir = self._find_metadata_directory()
            if metadata_dir:
                base_name = os.path.basename(base_name)
                for pattern in metadata_patterns:
                    meta_file = os.path.join(metadata_dir, base_name + pattern)
                    if os.path.exists(meta_file):
                        metadata_path = meta_file
                        break
        
        return signature_path, metadata_path

    def _find_metadata_directory(self):
        """Recherche le dossier des métadonnées"""
        possible_dirs = [
            "metadata",
            "meta",
            "info",
            "data"
        ]
        
        # Recherche dans le répertoire de base
        for dir_name in possible_dirs:
            dir_path = os.path.join(self.base_dir, dir_name)
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                return dir_path
        
        # Recherche dans les sous-répertoires
        for root, dirs, files in os.walk(self.base_dir):
            for dir_name in possible_dirs:
                if dir_name in dirs:
                    return os.path.abspath(os.path.join(root, dir_name))
        
        return None

    def verify_signature(self, file_path, signature_path):
        """Vérifie la signature d'un fichier"""
        try:
            # Lecture du fichier
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Lecture de la signature
            with open(signature_path, 'rb') as f:
                signature = f.read()
            
            # Vérification de la signature
            self.public_key.verify(
                signature,
                file_data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✅ Signature vérifiée avec succès")
            return True
        except Exception as e:
            print(f"❌ Erreur lors de la vérification de la signature : {str(e)}")
            return False

    def decrypt_file(self, encrypted_file_path, aes_key_hex):
        """Déchiffre un fichier avec la clé AES"""
        try:
            # Conversion de la clé hexadécimale en bytes
            aes_key = bytes.fromhex(aes_key_hex)
            
            # Lecture du fichier chiffré
            with open(encrypted_file_path, 'rb') as f:
                # Lecture du IV (16 premiers bytes)
                iv = f.read(16)
                # Lecture des données chiffrées
                encrypted_data = f.read()
            
            # Création du cipher AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Déchiffrement
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Suppression du padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            # Création du fichier déchiffré
            decrypted_file_path = os.path.splitext(encrypted_file_path)[0]
            with open(decrypted_file_path, 'wb') as f:
                f.write(data)
            
            print(f"✅ Fichier déchiffré avec succès : {decrypted_file_path}")
            return decrypted_file_path
            
        except Exception as e:
            print(f"❌ Erreur lors du déchiffrement : {str(e)}")
            return None

def list_encrypted_files():
    """Liste tous les fichiers chiffrés disponibles"""
    # Définition du répertoire de base
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Recherche des fichiers chiffrés avec différentes extensions possibles
    encrypted_extensions = [".enc", ".encrypted", ".crypt", ".crypto"]
    encrypted_files = []
    
    # Recherche dans le répertoire de base
    for ext in encrypted_extensions:
        pattern = os.path.join(base_dir, f"*{ext}")
        found_files = glob.glob(pattern)
        # Ne garder que les fichiers qui ne sont pas des signatures
        encrypted_files.extend([f for f in found_files if not f.endswith('.sig')])
    
    if not encrypted_files:
        print("❌ Aucun fichier chiffré trouvé dans le répertoire.")
        return None
    
    print("\n📁 Fichiers chiffrés disponibles :")
    for i, file in enumerate(encrypted_files, 1):
        print(f"{i}. {os.path.basename(file)}")
    
    while True:
        try:
            choice = input("\nChoisissez le numéro du fichier à déchiffrer (0 pour quitter) : ").strip()
            if not choice:
                continue
            choice = int(choice)
            if choice == 0:
                return None
            if 1 <= choice <= len(encrypted_files):
                return encrypted_files[choice - 1]
            print("❌ Choix invalide. Veuillez réessayer.")
        except ValueError:
            print("❌ Veuillez entrer un numéro valide.")

def verify_and_decrypt_file(encrypted_file_path):
    """Fonction principale pour vérifier et déchiffrer un fichier"""
    try:
        # Création du vérificateur
        verifier = SecurityVerifier()
        
        # Construction des chemins des fichiers associés
        base_name = os.path.splitext(encrypted_file_path)[0]  # Enlève .enc
        signature_path = base_name + '.sig'
        
        # Construction du chemin des métadonnées
        # On utilise le nom du fichier original (sans .enc)
        original_name = os.path.basename(base_name)  # Enlève le chemin
        metadata_path = os.path.join(
            os.path.dirname(encrypted_file_path),
            "metadata",
            original_name + '.meta'
        )
        
        print(f"\n🔍 Recherche des fichiers associés :")
        print(f"  - Fichier chiffré : {os.path.basename(encrypted_file_path)}")
        print(f"  - Signature : {os.path.basename(signature_path)}")
        print(f"  - Métadonnées : {os.path.basename(metadata_path)}")
        
        # Vérification de l'existence des fichiers
        if not os.path.exists(encrypted_file_path):
            print(f"❌ Fichier chiffré non trouvé : {encrypted_file_path}")
            return False
        if not os.path.exists(signature_path):
            print(f"❌ Fichier de signature non trouvé : {signature_path}")
            return False
        if not os.path.exists(metadata_path):
            print(f"❌ Fichier de métadonnées non trouvé : {metadata_path}")
            return False
        
        # Lecture des métadonnées
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                print("✅ Métadonnées chargées avec succès")
        except Exception as e:
            print(f"❌ Erreur lors de la lecture des métadonnées : {str(e)}")
            return False
        
        # Vérification de la signature
        print("\n🔐 Vérification de la signature...")
        if not verifier.verify_signature(encrypted_file_path, signature_path):
            return False
        
        # Déchiffrement du fichier
        print("\n🔓 Déchiffrement du fichier...")
        decrypted_file = verifier.decrypt_file(encrypted_file_path, metadata['aes_key'])
        if decrypted_file:
            print("✅ Opération terminée avec succès")
            return True
        return False
        
    except Exception as e:
        print(f"❌ Erreur lors de la vérification et du déchiffrement : {str(e)}")
        return False

if __name__ == "__main__":
    print("🔓 Programme de vérification et déchiffrement de fichiers")
    print("=" * 50)
    while True:
        encrypted_file = list_encrypted_files()
        if encrypted_file is None:
            break
        print(f"\n📄 Fichier sélectionné : {os.path.basename(encrypted_file)}")
        verify_and_decrypt_file(encrypted_file)
        choice = input("\nVoulez-vous déchiffrer un autre fichier ? (o/n) : ").lower().strip()
        if choice != 'o':
            break
    print("\n👋 Au revoir !") 