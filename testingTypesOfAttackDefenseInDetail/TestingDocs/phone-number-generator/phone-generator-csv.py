import csv
import os

# ✅ Cambodian mobile prefix map
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

# 🔢 Number generation configuration
start = 100000
count_per_prefix = 10  # Change to 1000+ if needed
csv_filename = "generated_contacts.csv"

# 📝 Create contacts list
with open(csv_filename, "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    # Google + Outlook common columns
    writer.writerow(["Name", "Phone 1 - Type", "Phone 1 - Value", "First Name", "Mobile Phone"])

    for operator, data in prefix_map.items():
        for prefix in data["prefixes"]:
            is_seven = prefix in data["seven_digit_prefixes"]
            for i in range(start, start + count_per_prefix):
                number = f"+855{prefix}{str(i).zfill(7 if is_seven else 6)}"
                name = f"{operator}-{prefix}-{str(i).zfill(7 if is_seven else 6)}"
                writer.writerow([name, "Mobile", number, name, number])

print(f"✅ Contact CSV generated: {os.path.abspath(csv_filename)}")
