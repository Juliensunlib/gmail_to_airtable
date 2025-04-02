import os
import base64
import json
import time
import requests
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
    """Authentification Gmail et création du service."""
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_info(json.load(open(TOKEN_PATH)))
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        
        with open(TOKEN_PATH, 'w') as token:
            token.write(creds.to_json())
    
    return build('gmail', 'v1', credentials=creds)

def get_last_sync_time():
    """Récupère la date de dernière synchronisation."""
    if os.path.exists(LAST_SYNC_PATH):
        with open(LAST_SYNC_PATH, 'r') as f:
            data = json.load(f)
            return data.get('last_sync_time', 0)
    return 0  # Si pas de fichier, retourner 0 (= début des temps pour Gmail)

def save_last_sync_time(timestamp):
    """Sauvegarde la date de dernière synchronisation."""
    with open(LAST_SYNC_PATH, 'w') as f:
        json.dump({'last_sync_time': timestamp}, f)

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
    
    results = service.users().messages().list(userId='me', q=query, maxResults=100).execute()
    messages = results.get('messages', [])
    
    if not messages:
        print("Aucun nouvel email trouvé.")
        return []
    
    print(f"Traitement de {len(messages)} nouveaux emails.")
    
    # Pour suivre le timestamp le plus récent
    most_recent_timestamp = last_sync
    
    emails = []
    for message in messages:
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
        user_email = service.users().getProfile(userId='me').execute()['emailAddress']
        if 'expediteur' in email_data and user_email in email_data['expediteur']:
            email_data['statut'] = 'envoyé'
        else:
            email_data['statut'] = 'reçu'
        
        # Extraction du timestamp
        email_data['date_envoi'] = msg['internalDate']
        
        # Extraction du contenu
        email_data['contenu'] = extract_body(msg['payload'])
        
        emails.append(email_data)
    
    # Sauvegarder le timestamp le plus récent
    if most_recent_timestamp > last_sync:
        save_last_sync_time(most_recent_timestamp)
        
    return emails

def extract_body(payload):
    """Extraire le contenu de l'email récursivement."""
    if 'body' in payload and payload['body'].get('data'):
        return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
    
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                if part['body'].get('data'):
                    return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
            elif part['mimeType'] == 'multipart/alternative':
                return extract_body(part)
    
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
    
    response = requests.get(airtable_url, headers=headers, params=query_params)
    
    if response.status_code != 200:
        print(f"Erreur lors de la vérification dans Airtable: {response.text}")
        return False
    
    records = response.json().get('records', [])
    return len(records) > 0

def add_to_airtable(emails):
    """Ajout des emails à Airtable selon la structure spécifiée."""
    airtable_url = f'https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}'
    headers = {
        'Authorization': f'Bearer {AIRTABLE_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    added_count = 0
    for email in emails:
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
    
    return added_count

def main():
    """Fonction principale."""
    print("Démarrage de la synchronisation Gmail vers Airtable...")
    service = get_gmail_service()
    
    # Récupération des nouveaux emails depuis la dernière synchronisation
    emails = get_emails(service)
    
    if emails:
        added_count = add_to_airtable(emails)
        print(f"Synchronisation terminée. {added_count}/{len(emails)} emails ajoutés à Airtable.")
    else:
        print("Aucun nouvel email à traiter.")

if __name__ == '__main__':
    main()