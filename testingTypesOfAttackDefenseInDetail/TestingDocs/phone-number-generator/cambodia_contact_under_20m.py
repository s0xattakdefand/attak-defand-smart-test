import os
import csv

# Target max size per file (in bytes): 19MB to stay under Google's 20MB limit
MAX_FILE_SIZE = 19 * 1024 * 1024

output_dir = "chunked_contacts_google"
os.makedirs(output_dir, exist_ok=True)

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

def open_new_csv(index):
    path = os.path.join(output_dir, f"contacts_chunk_{index}.csv")
    file = open(path, "w", newline="", encoding="utf-8")
    writer = csv.writer(file)
    writer.writerow(["Name", "Phone 1 - Type", "Phone 1 - Value"])  # Google Contacts format
    return path, file, writer

file_index = 1
current_path, current_file, writer = open_new_csv(file_index)

for operator, data in prefix_map.items():
    for prefix in data["prefixes"]:
        is_7digit = prefix in data["seven_digit_prefixes"]
        max_range = 10_000_000 if is_7digit else 1_000_000

        for i in range(max_range):
            subscriber = str(i).zfill(7 if is_7digit else 6)
            phone = f"+855{prefix}{subscriber}"
            name = f"{operator}-{prefix}-{subscriber}"
            writer.writerow([name, "Mobile", phone])

            # Check file size
            if os.path.getsize(current_path) >= MAX_FILE_SIZE:
                current_file.close()
                file_index += 1
                current_path, current_file, writer = open_new_csv(file_index)

current_file.close()
print(f"✅ DONE. Files created in '{output_dir}' — all under 20MB for Google Contacts import.")
