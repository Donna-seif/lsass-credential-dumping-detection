import json

# Known suspicious access rights (example values)
suspicious_access = ["0x1010", "0x1038", "0x1438", "0x1fffff"]

# Trusted processes (example)
trusted_processes = ["MsMpEng.exe"]

with open("process_injection_logs.json", "r") as file:
    logs = json.load(file)

for log in logs:
    score = 0

    target = log.get("TargetImage", "").lower()
    source = log.get("SourceImage", "")
    access = log.get("GrantedAccess", "").lower()
    signed = log.get("Signed", "True")

    # LSASS access
    if "lsass.exe" in target:
        score += 1

    # Suspicious access rights
    if access in suspicious_access:
        score += 2

    # Unsigned process
    if signed == "False":
        score += 1

    # Not a trusted process
    if source not in trusted_processes:
        score += 1

    if score >= 4:
        print("🚨 High confidence alert:", log)
