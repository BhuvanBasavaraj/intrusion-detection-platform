from log_parser import load_logs


logs = load_logs("data/security_logs.csv")

print(f"Loaded {len(logs)} events")

for log in logs:
    print(log)