from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import paramiko
import os
import json
from datetime import datetime

class SecurityManager:
    def __init__(self):
        self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
        os.makedirs(self.keys_dir, exist_ok=True)
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        self._save_keys()

    def _save_keys(self):
        private_key_path = os.path.join(self.keys_dir, "private_key.pem")
        public_key_path = os.path.join(self.keys_dir, "public_key.pem")
        
        with open(private_key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(public_key_path, "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def encrypt_and_sign_file(self, file_path):
        # Étape 1: Chiffrement AES
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Étape 2: Création du fichier chiffré
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv)
            f.write(encrypted_data)
        
        # Étape 3: Signature du fichier chiffré
        with open(encrypted_file_path, 'rb') as f:
            encrypted_file_data = f.read()
        
        signature = self.private_key.sign(
            encrypted_file_data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Étape 4: Création du fichier final (chiffré + signature)
        final_file_path = file_path + '.secure'
        with open(final_file_path, 'wb') as f:
            # En-tête: longueur de la signature (4 bytes)
            f.write(len(signature).to_bytes(4, byteorder='big'))
            # Signature
            f.write(signature)
            # Données chiffrées
            f.write(encrypted_file_data)
        
        # Nettoyage des fichiers temporaires
        os.remove(encrypted_file_path)
        
        # Création des métadonnées
        metadata = {
            'timestamp': datetime.now().isoformat(),
            'original_file': os.path.basename(file_path),
            'secure_file': os.path.basename(final_file_path),
            'aes_key': aes_key.hex()
        }
        
        metadata_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metadata")
        os.makedirs(metadata_dir, exist_ok=True)
        
        metadata_file = os.path.join(metadata_dir, os.path.basename(file_path) + '.meta')
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)
        
        return final_file_path, metadata_file

    def send_secure_file(self, file_path, hostname, username, password=None, key_path=None):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if key_path:
                ssh.connect(hostname, username=username, key_filename=key_path)
            else:
                ssh.connect(hostname, username=username, password=password)
            
            sftp = ssh.open_sftp()
            
            try:
                sftp.mkdir(f"/home/{username}/rapports")
            except:
                pass
            
            remote_path = f"/home/{username}/rapports/{os.path.basename(file_path)}"
            sftp.put(file_path, remote_path)
            
            sftp.close()
            ssh.close()
            
            return True, f"Secure file successfully sent to {remote_path}"
            
        except Exception as e:
            return False, f"Error sending secure file: {str(e)}"

def process_report(report_path, hostname=None, username=None, password=None, key_path=None):
    try:
        security_manager = SecurityManager()
        
        # Chiffrement et signature du rapport
        secure_file_path, metadata_file = security_manager.encrypt_and_sign_file(report_path)
        
        if hostname and username:
            # Envoi du fichier sécurisé via SFTP
            success, message = security_manager.send_secure_file(
                secure_file_path,
                hostname,
                username,
                password,
                key_path
            )
            
            if success:
                # Envoi des métadonnées
                security_manager.send_secure_file(
                    metadata_file,
                    hostname,
                    username,
                    password,
                    key_path
                )
            
            return success, message
        else:
            return True, "Report secured locally"
        
    except Exception as e:
        return False, f"Error processing report: {str(e)}"

def check_available_reports():
    reports = []
    if os.path.exists("rapport_vulnerabilites.pdf"):
        reports.append("rapport_vulnerabilites.pdf")
    if os.path.exists("rapport_reseau.pdf"):
        reports.append("rapport_reseau.pdf")
    return reports

def main():
    print("Report Security System")
    print("=====================")
    
    available_reports = check_available_reports()
    if not available_reports:
        print("No reports available for processing.")
        return
    
    print("\nAvailable reports:")
    for i, report in enumerate(available_reports, 1):
        print(f"{i}. {report}")
    
    while True:
        try:
            choice = input("\nSelect report number to process (0 to exit): ").strip()
            if not choice:
                continue
            choice = int(choice)
            if choice == 0:
                break
            if 1 <= choice <= len(available_reports):
                selected_report = available_reports[choice - 1]
                
                print("\nConfigure SFTP transfer:")
                hostname = input("SFTP server address (leave empty for local storage): ").strip()
                
                if hostname:
                    username = input("SFTP username: ").strip()
                    auth_choice = input("Use SSH key? (y/n): ").lower().strip()
                    
                    if auth_choice == 'y':
                        key_path = input("SSH private key path: ").strip()
                        password = None
                    else:
                        password = input("SFTP password: ").strip()
                        key_path = None
                    
                    success, message = process_report(
                        selected_report,
                        hostname=hostname,
                        username=username,
                        password=password,
                        key_path=key_path
                    )
                    
                    if success:
                        print("Report successfully secured and transferred")
                    else:
                        print(f"Error: {message}")
                else:
                    success, message = process_report(selected_report)
                    if success:
                        print("Report successfully secured locally")
                    else:
                        print(f"Error: {message}")
                
                if len(available_reports) > 1:
                    continue_choice = input("\nProcess another report? (y/n): ").lower().strip()
                    if continue_choice != 'y':
                        break
                else:
                    break
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")
    
    print("\nProcess completed.")

if __name__ == "__main__":
    main() 