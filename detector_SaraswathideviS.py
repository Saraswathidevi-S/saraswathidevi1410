import csv
import json
import re
import sys
from typing import Dict, List, Tuple, Any


class PIIDetector:
    def __init__(self):
        self.phone_pattern = re.compile(r"^\d{10}$")
        self.aadhar_pattern = re.compile(r"^\d{12}$")
        self.passport_pattern = re.compile(r"^[A-Z]\d{7}$")
        self.upi_pattern = re.compile(r"^[\w.-]+@[\w.-]+$|^\d{10}@\w+$")
        self.email_pattern = re.compile(
            r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$"
        )

    def is_standalone_pii(self, key: str, value: Any) -> bool:
        if not value:
            return False

        value_str = str(value).strip()
        if key in ["phone", "contact"]:
            return self.phone_pattern.match(value_str) is not None
        if key == "aadhar":
            return self.aadhar_pattern.match(value_str) is not None
        if key == "passport":
            return self.passport_pattern.match(value_str) is not None
        if key == "upi_id":
            return self.upi_pattern.match(value_str) is not None
        return False

    def is_full_name(self, value: str) -> bool:
        if not isinstance(value, str):
            return False
        
        parts = value.strip().split()
        if len(parts) >= 2:
            return all(
                part.replace("-", "").replace("'", "").isalpha() for part in parts
            )
        return False

    def is_physical_address(self, value: str) -> bool:
        if not isinstance(value, str):
            return False

        value_lower = value.lower()
        has_number = bool(re.search(r"\d+", value))
        has_comma = "," in value
        word_count = len(value.split()) >= 5
        has_pincode = bool(re.search(r"\b\d{6}\b", value))
        address_keywords = [
            "road",
            "street",
            "lane",
            "avenue",
            "nagar",
            "colony",
            "park",
        ]
        has_keyword = any(keyword in value_lower for keyword in address_keywords)

        return (has_number and has_comma and word_count) or (
            has_pincode and has_keyword
        )

    def detect_combinatorial_pii(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        found_pii = []

        for key, value in data.items():
            if not value:
                continue

            value_str = str(value).strip()
            if key == "name" and self.is_full_name(value_str):
                found_pii.append("name")
            elif key == "email" and self.email_pattern.match(value_str):
                found_pii.append("email")
            elif key == "address" and self.is_physical_address(value_str):
                found_pii.append("address")
            elif key in ["device_id", "ip_address"] and value:
                user_context_keys = {"name", "email"}
                if any(k in data and data[k] for k in user_context_keys):
                    if ("name" in data and self.is_full_name(str(data["name"]))) or (
                        "email" in data and self.email_pattern.match(str(data["email"]))
                    ):
                        found_pii.append(key)

        return len(found_pii) >= 2, found_pii

    def mask_value(self, key: str, value: str) -> str:
        if not value:
            return value

        value_str = str(value).strip()
        if key in ["phone", "contact"]:
            if len(value_str) == 10 and value_str.isdigit():
                return f"{value_str[:2]}XXXXXX{value_str[-2:]}"
        if key == "aadhar":
            if len(value_str) == 12 and value_str.isdigit():
                return f"{value_str[:4]}XXXX{value_str[-4:]}"
        if key == "email" and "@" in value_str:
            parts = value_str.split("@")
            if len(parts) == 2:
                local = parts[0]
                if len(local) > 2:
                    masked_local = local[:2] + "XXX"
                else:
                    masked_local = "XXX"
                return f"{masked_local}@{parts[1]}"

        if key == "name":
            parts = value_str.split()
            if len(parts) >= 2:
                first = parts[0]
                last = parts[-1]
                masked_first = first[0] + "XXX" if first else "XXX"
                masked_last = last[0] + "XXXX" if last else "XXXX"
                return f"{masked_first} {masked_last}"
            
        if key == "address":
            if len(value_str) > 15:
                return value_str[:10] + "... [REDACTED]"

        if key == "upi_id":
            if "@" in value_str:
                parts = value_str.split("@")
                if len(parts) == 2:
                    user_part = parts[0]
                    if len(user_part) > 3:
                        masked_user = user_part[:3] + "XXX"
                    else:
                        masked_user = "XXX"
                    return f"{masked_user}@{parts[1]}"

        if key == "passport":
            if (
                len(value_str) == 8
                and value_str[0].isalpha()
                and value_str[1:].isdigit()
            ):
                return f"{value_str[0]}XXX{value_str[-4:]}"

        return "[REDACTED_PII]"

    def process_record(self, record: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        is_pii = False
        redacted_data = {}

        for key, value in record.items():
            if value and self.is_standalone_pii(key, value):
                is_pii = True
                redacted_data[key] = self.mask_value(key, str(value))
            else:
                redacted_data[key] = value

        if not is_pii:
            has_combinatorial, found_fields = self.detect_combinatorial_pii(record)
            if has_combinatorial:
                is_pii = True
                for field in found_fields:
                    if field in record and record[field]:
                        redacted_data[field] = self.mask_value(
                            field, str(record[field])
                        )

        return redacted_data, is_pii

def format_json_for_csv(data: Dict[str, Any]) -> str:
    json_str = json.dumps(data, separators=(",", ": "))
    return json_str.replace('"', '""')

def main(input_file: str):
    detector = PIIDetector()
    output_csv = "redacted_output_SaraswathideviS.csv"
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
        delimiter = "\t" if "\t" in first_line else ","
        with open(input_file, "r", encoding="utf-8") as infile, open(
            output_csv, "w", encoding="utf-8", newline=""
        ) as csvfile:
            infile.seek(0)
            first_char = infile.read(1)
            if first_char != "\ufeff":
                infile.seek(0)
            reader = csv.DictReader(infile, delimiter=delimiter)
            header = "record_id,redacted_data_json,is_pii"
            csvfile.write(header + "\n")
            records_processed = 0
            pii_detected = 0

            for row in reader:
                record_id = row.get("record_id", row.get("record_id\ufeff", "")).strip()
                data_json = row.get("data_json", row.get("Data_json", "{}")).strip()
                if not record_id or not data_json:
                    continue
                try:
                    data = json.loads(data_json)
                    redacted_data, is_pii = detector.process_record(data)
                    records_processed += 1
                    if is_pii:
                        pii_detected += 1
                    formatted_json = format_json_for_csv(redacted_data)
                    output_line = f'{record_id},"{formatted_json}",{is_pii}'
                    csvfile.write(output_line + "\n")

                except json.JSONDecodeError as e:
                    print(f"Error in the JSON record at {record_id}, attempting to fix")
                  
                    s = re.sub(r'"}\s*"$', '"}', data_json.strip())
                    s = re.sub(r'"\s*"$', '"', s)
                    s = re.sub(r':\s*(\d{4}-\d{2}-\d{2}|[A-Za-z_]+)(?=[},"])', r': "\1"', s)
                    s = re.sub(r'""(?=\s*[}\]])', '"', s)

                    try:
                        data = json.loads(s)
                        redacted_data, is_pii = detector.process_record(data)
                        formatted_json = format_json_for_csv(redacted_data)
                        output_line = f'{record_id},"{formatted_json}",{is_pii}'
                        csvfile.write(output_line + "\n")
                    except Exception as inner_e:
                        print(f"Attempting to fix it failed: {record_id}: {inner_e}")
                        s_csv = s.replace('"', '""')
                        output_line = f'{record_id},"{s_csv}",Error'
                        csvfile.write(output_line + "\n")

                except Exception as e:
                    print(f"Error processing record {record_id}: {e}")
                    continue

    except FileNotFoundError:
        sys.exit(1)
    except Exception as e:
        print(f"Error in file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print(f"Records processed: {records_processed}")
    print(f"PII records detected: {pii_detected}")
    print(f"Output saved as: {output_csv}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)

    main(sys.argv[1])
