import os
import csv

output_dir = "chunked_contacts"
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

chunk_size = 1_000_000
contact_count = 0
file_index = 1

file = open(os.path.join(output_dir, f"contacts_chunk_{file_index}.csv"), "w", newline="", encoding="utf-8")
writer = csv.writer(file)
writer.writerow(["Name", "Phone 1 - Type", "Phone 1 - Value"])

for operator, data in prefix_map.items():
    for prefix in data["prefixes"]:
        is_7digit = prefix in data["seven_digit_prefixes"]
        max_range = 10_000_000 if is_7digit else 1_000_000

        for i in range(max_range):
            if contact_count >= chunk_size:
                file.close()
                file_index += 1
                contact_count = 0
                file = open(os.path.join(output_dir, f"contacts_chunk_{file_index}.csv"), "w", newline="", encoding="utf-8")
                writer = csv.writer(file)
                writer.writerow(["Name", "Phone 1 - Type", "Phone 1 - Value"])

            subscriber = str(i).zfill(7 if is_7digit else 6)
            phone = f"+855{prefix}{subscriber}"
            name = f"{operator}-{prefix}-{subscriber}"
            writer.writerow([name, "Mobile", phone])
            contact_count += 1

file.close()
print(f"✅ DONE. Created {file_index} files in {output_dir}/")
