import json

COMPLIANCE_CONTROLS = {
    "GDPR": ["encryption_at_rest", "role_based_access", "file_audit_log", "data_retention_policy"],
    "HIPPA": ["encryption_in_transit", "role_based_access", "access_logging", "file_integrity", "incident_response"],
    "ISO27001": ["encryption_at_rest", "encryption_in_transit", "user_authentication", "audit_logging", "least_privilege"],
}

CONTROL_IMPLEMENTATION = {
    "encryption_at_rest": True,
    "encryption_in_transit": True,
    "role_based_access": True,
    "file_audit_log": True,
    "user_authentication": True,
    "access_logging": True,
    "file_integrity": True,
    "data_retention_policy": True,
    "incident_response": True,
    "least_privilege": True,
}

def map_controls_to_frameworks():
    compliance_report = {}
    for framework, required_controls in COMPLIANCE_CONTROLS.items():
        satisfied = []
        missing = []
        for control in required_controls:
            if CONTROL_IMPLEMENTATION.get(control):
                satisfied.append(control)
            else:
                missing.append(control)
        compliance_report[framework] = {
            "satisfied": satisfied,
            "missing": missing
        }
        with open("compliance_report.json", "w") as out:
            json.dump(compliance_report, out, indent=2)
        print("Compliance mapping complete:")
        print(json.dumps(compliance_report, indent=2))

def validate_logging():
    try:
        with open("audit_log.json", "r") as f:
            logs = json.load(f)
    except Exception:
        logs = []

    problems = []
    for entry in logs:
        if not all(l in entry for k in ["user", "action", "timestamp", "file"]):
            problems.append(entry)
    
    with open("log_integrity_report.json", "w") as out:
        json.dump({"invalid_entries": problems}, out, indent=2)
    print(f"Log audit complete. Found {len(problems)} invalid log entries.")

if __name__ == "__main__":
    map_controls_to_frameworks()
    validate_logging()