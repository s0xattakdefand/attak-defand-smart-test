import os
import csv

# Set chunk size based on Google's max import limit
CHUNK_CONTACT_LIMIT = 24690

# Output directory
output_dir = "contacts_google_chunks"
os.makedirs(output_dir, exist_ok=True)

# Cambodian prefixes and 7-digit rules
prefix_map = {
    "Mobitel": {
        "prefixes": ["011", "012", "017", "061", "076", "077", "078", "079", "085", "089", "092", "095", "099"],
        "seven_digit_prefixes": ["076", "079"]
    },
    "Smart": {
        "prefixes": ["010", "015", "016", "069", "070", "081", "086", "087", "093", "096", "098"],
        "seven_digit_prefixes": ["096"]
    },
    "Metfone": {
        "prefixes": ["031", "060", "066", "068", "071", "088", "090"],
        "seven_digit_prefixes": ["031", "071", "088", "079"]
    }
}

def open_new_csv(file_index):
    file_path = os.path.join(output_dir, f"contacts_chunk_{file_index}.csv")
    f = open(file_path, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["Name", "Phone 1 - Type", "Phone 1 - Value"])  # Google Contacts format
    return file_path, f, w

file_index = 1
contact_count = 0
current_path, current_file, writer = open_new_csv(file_index)

for operator, data in prefix_map.items():
    for prefix in data["prefixes"]:
        is_7digit = prefix in data["seven_digit_prefixes"]
        max_range = 10_000_000 if is_7digit else 1_000_000

        for i in range(max_range):
            if contact_count >= CHUNK_CONTACT_LIMIT:
                current_file.close()
                file_index += 1
                contact_count = 0
                current_path, current_file, writer = open_new_csv(file_index)

            subscriber = str(i).zfill(7 if is_7digit else 6)
            number = f"+855{prefix}{subscriber}"
            name = f"{operator}-{prefix}-{subscriber}"
            writer.writerow([name, "Mobile", number])
            contact_count += 1

current_file.close()
print(f"✅ Done: Generated {file_index} CSV files with up to 24,690 contacts each in '{output_dir}/'")
