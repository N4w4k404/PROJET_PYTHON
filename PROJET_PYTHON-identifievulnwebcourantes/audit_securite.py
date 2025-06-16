import paramiko
import os
import sys
import socket
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import json

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('audit_securite.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class AuditSecurite:
    def __init__(self):
        """Initialise l'outil d'audit de sécurité"""
        self.rapport = {
            "date_audit": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ports_ouverts": [],
            "anomalies_reseau": [],
            "vulnerabilites_web": {
                "xss": [],
                "sql_injection": [],
                "autres": []
            }
        }
        
        # Dictionnaires de vulnérabilités
        self.dictionnaire_xss = {
            "XSS-001": {
                "payload": "<script>alert('XSS')</script>",
                "url": "/search?q="
            },
            "XSS-002": {
                "payload": "<img src=x onerror=alert('XSS')>",
                "url": "/comment"
            },
            "XSS-003": {
                "payload": "javascript:alert('XSS')",
                "url": "/profile"
            },
            "XSS-004": {
                "payload": "<svg/onload=alert('XSS')>",
                "url": "/message"
            }
        }
        
        self.dictionnaire_sql = {
            "SQL-001": {
                "payload": "' OR '1'='1",
                "url": "/login"
            },
            "SQL-002": {
                "payload": "'; DROP TABLE users; --",
                "url": "/admin"
            },
            "SQL-003": {
                "payload": "' UNION SELECT * FROM users; --",
                "url": "/search"
            },
            "SQL-004": {
                "payload": "admin' --",
                "url": "/auth"
            }
        }
        
        # Génération des clés
        self.generer_cles()

    def generer_cles(self):
        """Génère les clés de chiffrement et de signature"""
        try:
            # Génération de la clé AES
            self.cle_aes = Fernet.generate_key()
            self.cipher_suite = Fernet(self.cle_aes)
            
            # Génération de la paire de clés RSA
            self.cle_privee = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.cle_publique = self.cle_privee.public_key()
            
            # Sauvegarde des clés
            self.sauvegarder_cles()
            logging.info("Clés générées et sauvegardées avec succès")
            
        except Exception as e:
            logging.error(f"Erreur lors de la génération des clés: {str(e)}")
            raise

    def sauvegarder_cles(self):
        """Sauvegarde les clés dans des fichiers"""
        try:
            # Sauvegarde de la clé AES
            with open('cle_aes.key', 'wb') as f:
                f.write(self.cle_aes)
            
            # Sauvegarde de la clé privée RSA
            with open('cle_privee.pem', 'wb') as f:
                f.write(self.cle_privee.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Sauvegarde de la clé publique RSA
            with open('cle_publique.pem', 'wb') as f:
                f.write(self.cle_publique.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
                
        except Exception as e:
            logging.error(f"Erreur lors de la sauvegarde des clés: {str(e)}")
            raise

    def ajouter_port_ouvert(self, port, service):
        """Ajoute un port ouvert au rapport"""
        self.rapport["ports_ouverts"].append({
            "port": port,
            "service": service,
            "severite": "MOYENNE"
        })

    def ajouter_anomalie_reseau(self, type_anomalie, description, severite):
        """Ajoute une anomalie réseau au rapport"""
        self.rapport["anomalies_reseau"].append({
            "type": type_anomalie,
            "description": description,
            "severite": severite
        })

    def ajouter_vulnerabilite_web(self, type_vuln, url, description, severite):
        """Ajoute une vulnérabilité web au rapport"""
        self.rapport["vulnerabilites_web"][type_vuln].append({
            "url": url,
            "description": description,
            "severite": severite
        })

    def generer_rapport(self):
        """Génère le rapport d'audit"""
        try:
            # Conversion du rapport en JSON
            rapport_json = json.dumps(self.rapport, indent=4)
            
            # Sauvegarde du rapport
            with open('rapport_audit.json', 'w') as f:
                f.write(rapport_json)
            
            logging.info("Rapport généré avec succès")
            return rapport_json
            
        except Exception as e:
            logging.error(f"Erreur lors de la génération du rapport: {str(e)}")
            raise

    def chiffrer_rapport(self, rapport):
        """Chiffre le rapport avec AES"""
        try:
            # Chiffrement du rapport
            rapport_chiffre = self.cipher_suite.encrypt(rapport.encode())
            
            # Sauvegarde du rapport chiffré
            with open('rapport_chiffre.bin', 'wb') as f:
                f.write(rapport_chiffre)
            
            logging.info("Rapport chiffré avec succès")
            return rapport_chiffre
            
        except Exception as e:
            logging.error(f"Erreur lors du chiffrement du rapport: {str(e)}")
            raise

    def signer_rapport(self, rapport_chiffre):
        """Signe le rapport chiffré avec RSA"""
        try:
            # Création de la signature
            signature = self.cle_privee.sign(
                rapport_chiffre,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Sauvegarde de la signature
            with open('signature_rapport.bin', 'wb') as f:
                f.write(signature)
            
            logging.info("Rapport signé avec succès")
            return signature
            
        except Exception as e:
            logging.error(f"Erreur lors de la signature du rapport: {str(e)}")
            raise

    def transferer_rapport(self, hote, utilisateur, mot_de_passe=None, chemin_cle=None):
        """Transfère le rapport vers un serveur distant via SFTP"""
        ssh = None
        sftp = None
        try:
            # Vérification de l'existence des fichiers à transférer
            fichiers_a_transferer = ['rapport_chiffre.bin', 'signature_rapport.bin']
            for fichier in fichiers_a_transferer:
                if not os.path.exists(fichier):
                    raise FileNotFoundError(f"Le fichier {fichier} n'existe pas")
                logging.info(f"Fichier {fichier} trouvé localement")

            # Création du client SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connexion au serveur
            try:
                logging.info(f"Tentative de connexion à {hote} avec l'utilisateur {utilisateur}")
                if chemin_cle:
                    ssh.connect(
                        hostname=hote,
                        username=utilisateur,
                        key_filename=chemin_cle,
                        timeout=30
                    )
                else:
                    ssh.connect(
                        hostname=hote,
                        username=utilisateur,
                        password=mot_de_passe,
                        timeout=30
                    )
                logging.info("Connexion SSH établie avec succès")
            except Exception as e:
                raise Exception(f"Erreur de connexion SSH: {str(e)}")
            
            # Création de la session SFTP
            try:
                sftp = ssh.open_sftp()
                logging.info("Session SFTP créée avec succès")
            except Exception as e:
                raise Exception(f"Erreur lors de la création de la session SFTP: {str(e)}")
            
            # Transfert des fichiers
            try:
                for fichier in fichiers_a_transferer:
                    chemin_distant = f"uploads/{fichier}"  # Dossier uploads sur le serveur
                    logging.info(f"Tentative de transfert de {fichier} vers {chemin_distant}")
                    sftp.put(fichier, chemin_distant)
                    logging.info(f"Fichier {fichier} transféré avec succès")
            except Exception as e:
                raise Exception(f"Erreur lors du transfert des fichiers: {str(e)}")
            
            logging.info("Rapport transféré avec succès")
            
        except Exception as e:
            logging.error(f"Erreur lors du transfert du rapport: {str(e)}")
            raise
        finally:
            # Fermeture des connexions
            if sftp:
                try:
                    sftp.close()
                    logging.info("Session SFTP fermée")
                except:
                    pass
            if ssh:
                try:
                    ssh.close()
                    logging.info("Connexion SSH fermée")
                except:
                    pass

def main():
    # Création de l'outil d'audit
    audit = AuditSecurite()
    
    # Exemple d'ajout de données au rapport
    audit.ajouter_port_ouvert(80, "HTTP")
    audit.ajouter_port_ouvert(443, "HTTPS")
    audit.ajouter_anomalie_reseau(
        "SYN Flood",
        "Détection d'une attaque SYN Flood",
        "HAUTE"
    )
    audit.ajouter_vulnerabilite_web(
        "xss",
        "http://example.com/login",
        "Vulnérabilité XSS détectée",
        "MOYENNE"
    )
    
    # Génération et sécurisation du rapport
    rapport = audit.generer_rapport()
    rapport_chiffre = audit.chiffrer_rapport(rapport)
    signature = audit.signer_rapport(rapport_chiffre)
    
    # Transfert du rapport (exemple avec serveur local)
    try:
        audit.transferer_rapport(
            hote='localhost',
            utilisateur='floriau',
            mot_de_passe='JeRouleEnR6'
        )
    except Exception as e:
        logging.error(f"Erreur lors du transfert: {str(e)}")
        logging.info("Le rapport a été généré localement mais n'a pas pu être transféré")

if __name__ == "__main__":
    main() 