import os
import csv
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- Configuration ---
SCOPES = ['https://www.googleapis.com/auth/contacts']
CREDENTIALS_FILE = 'credentials.json'
CSV_FOLDER = 'contacts'  # Folder with chunked .csv files

def authenticate():
    """Authenticate and return Google People API service."""
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
    creds = flow.run_local_server(port=0)
    service = build('people', 'v1', credentials=creds)
    return service

def import_contacts_from_csv(service, csv_file):
    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get("Name", "")
            phone = row.get("Phone 1 - Value", "")
            if phone:
                try:
                    contact_body = {
                        "names": [{"givenName": name}],
                        "phoneNumbers": [{"value": phone, "type": "mobile"}]
                    }
                    service.people().createContact(body=contact_body).execute()
                    print(f"✅ Imported: {name} → {phone}")
                except Exception as e:
                    print(f"❌ Error for {phone}: {e}")

def main():
    service = authenticate()
    files = sorted(f for f in os.listdir(CSV_FOLDER) if f.endswith('.csv'))

    for file in files:
        file_path = os.path.join(CSV_FOLDER, file)
        print(f"📤 Importing from: {file_path}")
        import_contacts_from_csv(service, file_path)

    print("✅ All files imported.")

if __name__ == "__main__":
    main()
