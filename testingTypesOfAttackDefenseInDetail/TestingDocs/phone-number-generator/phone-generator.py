import os
import logging
import argparse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define prefixes for each operator and their special digit length cases
operators = {
    "Mobitel": {
        "prefixes": ["011", "012", "017", "061", "076", "077", "078", "079", "085", "089", "092", "095", "099"],
        "seven_digit_prefixes": ["076"]
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

# Function to validate the range and increment values
def validate_range(start, end, increment):
    if start >= end:
        raise ValueError("start_number must be less than end_number")
    if increment <= 0:
        raise ValueError("increment must be greater than zero")
    if (end - start) < increment:
        raise ValueError("increment must be less than the range from start_number to end_number")

# Function to generate phone numbers and write them to files
def generate_phone_numbers(operators, start_number, end_number, increment, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for operator, details in operators.items():
        for prefix in details["prefixes"]:
            # Determine the digit length
            digit_length = 7 if prefix in details["seven_digit_prefixes"] else 6
            
            current_start_number = start_number
            while current_start_number <= end_number:
                # Create the list of phone numbers
                phone_numbers = [f"+855 {prefix} {str(i).zfill(digit_length)}" for i in range(current_start_number, min(current_start_number + increment, end_number + 1))]
                
                # Save the phone numbers to SQL file
                file_index = current_start_number // increment
                file_path = os.path.join(output_dir, f'{operator.lower()}_{prefix}_{file_index}.sql')
                with open(file_path, 'w') as file:
                    file.write("INSERT INTO phone_numbers (number) VALUES\n")
                    for i, number in enumerate(phone_numbers):
                        if i != len(phone_numbers) - 1:
                            file.write(f"('{number}'),\n")
                        else:
                            file.write(f"('{number}');\n")
                
                logging.info(f"Generated file: {file_path} with {len(phone_numbers)} phone numbers.")
                current_start_number += increment
    
    logging.info("Phone number generation completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate phone numbers and save them to SQL files.")
    parser.add_argument("--start_number", type=int, default=100000, help="The starting number to append to the base phone number.")
    parser.add_argument("--end_number", type=int, default=999999, help="The ending number to append to the base phone number.")
    parser.add_argument("--increment", type=int, default=55000, help="The increment for each file.")
    parser.add_argument("--output_dir", type=str, default="output", help="The directory to save the generated files.")
    
    args = parser.parse_args()
    
    try:
        validate_range(args.start_number, args.end_number, args.increment)
        generate_phone_numbers(operators, args.start_number, args.end_number, args.increment, args.output_dir)
    except ValueError as e:
        logging.error(f"Error: {e}")
