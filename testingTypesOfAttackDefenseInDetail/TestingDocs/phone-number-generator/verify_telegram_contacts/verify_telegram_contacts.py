import csv
import os
import time
from telethon.sync import TelegramClient
from telethon.tl.functions.contacts import ImportContactsRequest
from telethon.tl.types import InputPhoneContact

# === TELEGRAM API CONFIG ===
api_id = 25630631          # Replace with your actual Telegram API ID
api_hash = '4d770d2ba4be6283c4dc9af2b83377cb'    # Replace with your actual Telegram API hash
phone_number = '+85595217218'      # Replace with your actual phone number

contacts_folder = 'contacts'
output_folder = 'output_verified'
os.makedirs(output_folder, exist_ok=True)

BATCH_SIZE = 300
DELAY_SECONDS = 2

# === TELEGRAM CLIENT SESSION ===
client = TelegramClient('session_name', api_id, api_hash)
client.start(phone_number)

log_path = os.path.join(output_folder, "error_log.txt")
log_file = open(log_path, "a", encoding="utf-8")

summary_stats = []

for filename in os.listdir(contacts_folder):
    if not filename.endswith('.csv'):
        continue

    input_path = os.path.join(contacts_folder, filename)
    print(f"📥 Loading contacts from: {input_path}")

    with open(input_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    contacts = []
    for row in rows:
        name = row.get("Name", "")
        phone = row.get("Phone 1 - Value", "").replace(" ", "")
        if phone.startswith("+"):
            contacts.append(InputPhoneContact(client_id=0, phone=phone, first_name=name, last_name=""))

    print(f"✅ Loaded {len(contacts)} contacts from {filename}")

    success_count = 0
    failed_batches = 0

    for i in range(0, len(contacts), BATCH_SIZE):
        batch = contacts[i:i + BATCH_SIZE]
        try:
            print(f"📤 Sending batch {i // BATCH_SIZE + 1}...")
            result = client(ImportContactsRequest(batch))
            telegram_users = result.users
            success_count += len(telegram_users)

            for user in telegram_users:
                prefix = user.phone[3:6]  # assumes +855XXX...
                out_path = os.path.join(output_folder, f"verified_prefix_{prefix}.csv")
                with open(out_path, "a", newline="", encoding="utf-8") as out_file:
                    writer = csv.writer(out_file)
                    if out_file.tell() == 0:
                        writer.writerow(["Name", "Phone 1 - Type", "Phone 1 - Value"])
                    writer.writerow([user.first_name, "Mobile", f"+{user.phone}"])
        except Exception as e:
            failed_batches += 1
            log_file.write(f"❌ Telegram import failed for batch {i // BATCH_SIZE} in {filename}: {str(e)}\n")

        time.sleep(DELAY_SECONDS)

    summary_stats.append([filename, len(contacts) // BATCH_SIZE, success_count, failed_batches])
    print(f"✅ Finished {filename}: {success_count} Telegram users found, {failed_batches} failed batches")

log_file.close()
client.disconnect()

# === WRITE SUMMARY REPORT ===
summary_path = os.path.join(output_folder, "summary_report.csv")
with open(summary_path, "w", newline="", encoding="utf-8") as summary_file:
    writer = csv.writer(summary_file)
    writer.writerow(["Filename", "Batches", "VerifiedUsers", "FailedBatches"])
    writer.writerows(summary_stats)

print(f"✅ ALL DONE. Summary report saved to {summary_path}")