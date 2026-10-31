# NET2008 Practical Assessment 2
# Fleet Compliance Auditor
# Student Name: Khwaja Yousuf Mohiyuddeen
# Student Number: 041-263-017


import sys
import xml.etree.ElementTree as ET
import json

def main():
    """Read the XML inventory and display device IDs."""
    tree = ET.parse(sys.argv[1])
    root = tree.getroot()

    
    total_devices = 0
    skipped_devices = 0
    roles = {}
    interfaces = {"up": 0, "down": 0, "other": 0}

    for device in root.findall("device"):
        device_id = device.get("id")

        if not device_id:
            skipped_devices += 1
            continue

        total_devices += 1

        role = device.get("role", "")
        roles[role] = roles.get(role, 0) + 1

        for interface in device.findall("interface"):
            status = interface.get("status")

            if status == "up":
                interfaces["up"] += 1
            elif status == "down":
                interfaces["down"] += 1
            else:
                interfaces["other"] += 1

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
        "violations": [],
        "compliant": []
    }

    with open("audit.json", "w", encoding="utf-8") as file:
        json.dump(audit, file, indent=4)

    print("Audit report saved to audit.json")


if __name__ == "__main__":
    main()
