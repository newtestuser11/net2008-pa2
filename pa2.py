# NET2008 Practical Assessment 2
# Fleet Compliance Auditor
# Student Name: Khwaja Yousuf Mohiyuddeen
# Student Number: 041-263-017


import sys
import xml.etree.ElementTree as ET
import json
import yaml

class InputFileError(Exception):
    """An error with an input file."""
    pass

def main():
    """Check network devices and generate an audit report."""
    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    try:
        tree = ET.parse(sys.argv[1])
    except (OSError, ET.ParseError) as error:
        raise InputFileError(f"{sys.argv[1]}: {error}")

    root = tree.getroot()

    with open(sys.argv[2], "r", encoding="utf-8") as file:
        policy = yaml.safe_load(file)


    
    total_devices = 0
    skipped_devices = 0
    roles = {}
    violations = []
    compliant = []
    interfaces = {"up": 0, "down": 0, "other": 0}

    for device in root.findall("device"):
        device_id = device.get("id")

        if not device_id:
            skipped_devices += 1
            continue


        device_compliant = True
        total_devices += 1

        role = device.get("role", "")
        roles[role] = roles.get(role, 0) + 1
        
        if "min_os" in policy and role not in policy["min_os"]:
            violations.append({
                "device": device_id,
                "type": "unknown_role",
                "role": role
            })
            device_compliant = False

        if "min_os" in policy and role in policy["min_os"]:
            found = device.get("os")
            required = policy["min_os"][role]

            current = [int(x) for x in found.split(".")]
            minimum = [int(x) for x in required.split(".")]

            length = max(len(current), len(minimum))
            current += [0] * (length - len(current))
            minimum += [0] * (length - len(minimum))

            if current < minimum:
                violations.append({
                    "device": device_id,
                    "type": "os_outdated",
                    "found": found,
                    "required": required
                })
                device_compliant = False

        owner = device.find("owner")

        if policy.get("require_owner", False):
            if owner is None or not (owner.text or "").strip():
                violations.append({
                    "device": device_id,
                    "type": "missing_owner"
                })
                device_compliant = False

        down_count = 0
        for interface in device.findall("interface"):
            status = interface.get("status")

            if status == "up":
                interfaces["up"] += 1
            elif status == "down":
                interfaces["down"] += 1
                down_count += 1
            else:
                interfaces["other"] += 1

                
        if "max_down_interfaces" in policy:
            if down_count > policy["max_down_interfaces"]:
                violations.append({
                    "device": device_id,
                    "type": "too_many_down",
                    "down": down_count
                })
                device_compliant = False


        
        if device_compliant:
            compliant.append(device_id)



    print("Total devices:", total_devices)
    print("Skipped devices:", skipped_devices)
    print("Roles:", roles)
    print("Interfaces:", interfaces)


    audit = {
        "site": root.get("site"),
        "total_devices": total_devices,
        "skipped_devices": skipped_devices,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": sorted(compliant)
    }

    with open("audit.json", "w", encoding="utf-8") as file:
        json.dump(audit, file, indent=4)

    print("Audit report saved to audit.json")


if __name__ == "__main__":
    try:
        main()

    except InputFileError as error:
        print(f"Error: {error}")
        sys.exit(1)