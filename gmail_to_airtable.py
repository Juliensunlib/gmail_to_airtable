import os
import base64
import json
import time
import requests
import sys
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Chemins des fichiers
TOKEN_PATH = 'token.json'
CREDENTIALS_PATH = 'credentials.json'
LAST_SYNC_PATH = 'last_sync.json'  # Pour stocker la date de dernière synchronisation

# Définir les scopes pour l'accès Gmail
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Configuration Airtable - récupérer des variables d'environnement pour GitHub Actions
AIRTABLE_API_KEY = os.environ.get('AIRTABLE_API_KEY', 'YOUR_AIRTABLE_API_KEY')
AIRTABLE_BASE_ID = os.environ.get('AIRTABLE_BASE_ID', 'YOUR_AIRTABLE_BASE_ID')
AIRTABLE_TABLE_NAME = os.environ.get('AIRTABLE_TABLE_NAME', 'YOUR_TABLE_NAME')

def get_gmail_service():
    """Authentification Gmail et création du service avec gestion d'erreurs améliorée."""
    creds = None
    
    # Tentative de lecture du token
    if os.path.exists(TOKEN_PATH):
        try:
            with open(TOKEN_PATH, 'r') as token_file:
                token_content = token_file.read().strip()
                print(f"Premiers caractères du token : {token_content[:10]}...")
                
                # Tenter de charger le JSON
                creds_data = json.loads(token_content)
                creds = Credentials.from_authorized_user_info(creds_data)
                print("Token chargé avec succès")
        except json.JSONDecodeError as e:
            print(f"Erreur de décodage JSON du token : {e}")
            creds = None
        except Exception as e:
            print(f"Autre erreur lors du chargement du token : {e}")
            creds = None
    
    # Si pas de token valide, tenter l'authentification
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                print("Tentative de rafraîchissement du token...")
                creds.refresh(Request())
                print("Token rafraîchi avec succès")
            except Exception as e:
                print(f"Échec du rafraîchissement du token : {e}")
                creds = None
        
        # Si toujours pas de token, création d'un nouveau
        if not creds:
            try:
                print("Création d'un nouveau token...")
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
                
                # Détection environnement GitHub Actions ou autres environnements sans interface graphique
                if 'GITHUB_ACTIONS' in os.environ or 'CI' in os.environ:
                    print("Environnement sans interface graphique détecté (GitHub Actions)")
                    # Utiliser une méthode qui ne nécessite pas de navigateur
                    # En environnement CI, on doit déjà avoir un token valide fourni comme secret
                    print("Un token valide doit déjà exister dans l'environnement CI")
                    print("Si vous voyez cette erreur, vérifiez que votre secret GMAIL_TOKEN est correctement configuré")
                    sys.exit(1)
                else:
                    # En environnement normal, utiliser le navigateur
                    creds = flow.run_local_server(port=0)
                    print("Nouveau token créé avec succès")
            except Exception as e:
                print(f"Échec de la création d'un nouveau token : {e}")
                raise e  # On remonte l'erreur car impossible de continuer sans credentials
        
        # Sauvegarde du nouveau token
        try:
            with open(TOKEN_PATH, 'w') as token:
                token_json = creds.to_json()
                token.write(token_json)
                print("Token sauvegardé dans le fichier token.json")
        except Exception as e:
            print(f"Erreur lors de la sauvegarde du token : {e}")
    
    return build('gmail', 'v1', credentials=creds)

def get_last_sync_time():
    """Récupère la date de dernière synchronisation."""
    if os.path.exists(LAST_SYNC_PATH):
        try:
            with open(LAST_SYNC_PATH, 'r') as f:
                data = json.load(f)
                return data.get('last_sync_time', 0)
        except json.JSONDecodeError:
            print("Erreur de décodage du fichier de dernière synchronisation. Réinitialisation.")
            return 0
    return 0  # Si pas de fichier, retourner 0 (= début des temps pour Gmail)

def save_last_sync_time(timestamp):
    """Sauvegarde la date de dernière synchronisation."""
    try:
        with open(LAST_SYNC_PATH, 'w') as f:
            json.dump({'last_sync_time': timestamp}, f)
    except Exception as e:
        print(f"Erreur lors de la sauvegarde de la date de synchronisation : {e}")

def get_emails(service, query=''):
    """Récupération des emails Gmail (envoyés et reçus) depuis la dernière synchronisation."""
    last_sync = get_last_sync_time()
    
    # Ajouter une condition de date au query si on a une dernière synchronisation
    if last_sync > 0:
        after_date = int(last_sync / 1000)  # Convertir millisecondes en secondes
        date_query = f"after:{after_date}"
        if query:
            query = f"{query} {date_query}"
        else:
            query = date_query
    
    print(f"Recherche des emails avec query: {query}")
    
    try:
        results = service.users().messages().list(userId='me', q=query, maxResults=100).execute()
        messages = results.get('messages', [])
    except Exception as e:
        print(f"Erreur lors de la récupération des messages Gmail : {e}")
        return []
    
    if not messages:
        print("Aucun nouvel email trouvé.")
        return []
    
    print(f"Traitement de {len(messages)} nouveaux emails.")
    
    # Pour suivre le timestamp le plus récent
    most_recent_timestamp = last_sync
    
    emails = []
    for message in messages:
        try:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            
            # Mettre à jour le timestamp le plus récent
            internal_date = int(msg['internalDate'])
            if internal_date > most_recent_timestamp:
                most_recent_timestamp = internal_date
                
            email_data = {
                'email_id': message['id']  # Récupération de l'ID de l'email
            }
            
            # Extraction des en-têtes
            headers = msg['payload']['headers']
            for header in headers:
                if header['name'] == 'From':
                    email_data['expediteur'] = header['value']
                if header['name'] == 'To':
                    email_data['destinataire'] = header['value']
                if header['name'] == 'Subject':
                    email_data['sujet'] = header['value']
                if header['name'] == 'Date':
                    email_data['date_envoi_raw'] = header['value']
            
            # Déterminer le statut (envoyé ou reçu)
            try:
                user_email = service.users().getProfile(userId='me').execute()['emailAddress']
                if 'expediteur' in email_data and user_email in email_data['expediteur']:
                    email_data['statut'] = 'envoyé'
                else:
                    email_data['statut'] = 'reçu'
            except Exception as e:
                print(f"Erreur lors de la détermination du statut : {e}")
                email_data['statut'] = 'inconnu'
            
            # Extraction du timestamp
            email_data['date_envoi'] = msg['internalDate']
            
            # Extraction du contenu
            email_data['contenu'] = extract_body(msg['payload'])
            
            emails.append(email_data)
        except Exception as e:
            print(f"Erreur lors du traitement de l'email {message['id']} : {e}")
            continue
    
    # Sauvegarder le timestamp le plus récent
    if most_recent_timestamp > last_sync:
        save_last_sync_time(most_recent_timestamp)
        
    return emails

def extract_body(payload):
    """Extraire le contenu de l'email récursivement."""
    try:
        if 'body' in payload and payload['body'].get('data'):
            return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    if part['body'].get('data'):
                        return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                elif part['mimeType'] == 'multipart/alternative':
                    return extract_body(part)
    except Exception as e:
        print(f"Erreur lors de l'extraction du contenu de l'email : {e}")
    
    return ""

def check_email_exists(email_id):
    """Vérifie si un email existe déjà dans Airtable."""
    airtable_url = f'https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}'
    headers = {
        'Authorization': f'Bearer {AIRTABLE_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    # Filtrer par email_id
    filter_formula = f"email_id='{email_id}'"
    query_params = {'filterByFormula': filter_formula}
    
    try:
        response = requests.get(airtable_url, headers=headers, params=query_params)
        
        if response.status_code != 200:
            print(f"Erreur lors de la vérification dans Airtable: {response.text}")
            return False
        
        records = response.json().get('records', [])
        return len(records) > 0
    except Exception as e:
        print(f"Erreur lors de la vérification dans Airtable : {e}")
        return False

def add_to_airtable(emails):
    """Ajout des emails à Airtable selon la structure spécifiée."""
    if not AIRTABLE_API_KEY or AIRTABLE_API_KEY == 'YOUR_AIRTABLE_API_KEY':
        print("Erreur: Clé API Airtable non définie.")
        return 0
        
    airtable_url = f'https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}'
    headers = {
        'Authorization': f'Bearer {AIRTABLE_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    added_count = 0
    for email in emails:
        try:
            # Vérifier si l'email existe déjà
            if check_email_exists(email['email_id']):
                print(f"Email {email['email_id']} déjà présent dans Airtable.")
                continue
            
            # Préparation des données selon la structure Airtable
            data = {
                'fields': {
                    'email_id': email.get('email_id', ''),
                    'expediteur': email.get('expediteur', ''),
                    'destinataire': email.get('destinataire', ''),
                    'date_envoi': email.get('date_envoi_raw', ''),
                    'sujet': email.get('sujet', ''),
                    'contenu': email.get('contenu', ''),
                    'statut': email.get('statut', '')
                    # 'client_id': email.get('client_id', '')  # À compléter si nécessaire
                }
            }
            
            response = requests.post(airtable_url, headers=headers, json=data)
            if response.status_code == 200:
                print(f"Email {email['email_id']} ajouté à Airtable avec succès.")
                added_count += 1
            else:
                print(f"Erreur lors de l'ajout à Airtable: {response.text}")
        except Exception as e:
            print(f"Erreur lors de l'ajout de l'email {email.get('email_id', 'inconnu')} à Airtable : {e}")
    
    return added_count

def main():
    """Fonction principale."""
    print("Démarrage de la synchronisation Gmail vers Airtable...")
    
    try:
        service = get_gmail_service()
        
        # Récupération des nouveaux emails depuis la dernière synchronisation
        emails = get_emails(service)
        
        if emails:
            added_count = add_to_airtable(emails)
            print(f"Synchronisation terminée. {added_count}/{len(emails)} emails ajoutés à Airtable.")
        else:
            print("Aucun nouvel email à traiter.")
    except Exception as e:
        print(f"Erreur critique lors de l'exécution du script : {e}")
        # Sortir avec un code d'erreur pour signaler l'échec du workflow
        exit(1)

if __name__ == '__main__':
    main()
