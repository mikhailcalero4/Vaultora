import json
import re

def audit_privilege_escalation():
    try:
        with open("user_roles.json", "r") as f:
            roles = json.load(f)
    except Exception:
        roles = {}

    privileged_roles = {"admin"}
    findings = []
    for user, role in roles.items():
        if role in privileged_roles:
            #Check for multiple admins or unexpected role assignment
            findings.append({"user": user, "role": role})
        with open("privilege_escalation_report.json", "w") as out:
            json.dump(findings, out, indent=2)
        print(f"Privilege excalation audit complete. {len(findings)} privileged users found.")

def audit_input_validation():
    try:
        with open("audit_log.json", "r") as f:
            logs = json.load(f)
    except Exception:
        logs = []

    input_problems = []
    #Example: detect unexpected characters in file names
    valid_filename_regex = re.compile(r'^[\w,\s-]+\.[A-Za-z]{3,4}$')
    for entry in logs:
        file_name = entry.get("file", "")
        if not valid_filename_regex.match(file_name):
            input_problems.append({"user": entry.get("user", ""), "file": file_name})
    with open("input_validation_report.json", "w") as out:
        json.dump(input_problems, out, indent=2)
    print(f"Input validation audit complete. {len(input_problems)} problematic entries found.")

if __name__ == "__main__":
    audit_privilege_escalation()
    audit_input_validation()