import math
import os
import pickle
import re
import sys
import argparse

# Log parser
def parse_arguments(line_args):
    match = re.search(r'"[A-Z]+\s+([^\s?]+(?:\?[^\s"]+)?)"', line_args)
    if match:
        return match.group(1)
    return line_args.strip()

# Feature extraction functions
def compute_entropy(payload):
    """Calculates the Shannon entropy of a string."""
    if not payload:
        return 0
    entropy = 0
    length = len(payload)
    counts = {}
    for char in payload:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        probability = count / length
        entropy -= probability * (probability and math.log2(probability))
    return entropy

def count_special_chars(payload):
    """Counts characters heavily used in XSS, SQLi, and Command Injection."""
    special_chars = r"[<>\"'()\[\]{}%;&|]"
    return len(re.findall(special_chars, payload))

def count_keywords(payload):
    """Counts common malicious keywords used in attacks."""
    payload_lower = payload.lower()
    keywords = [
        "select", "union", "insert", "drop", "delete", "update", # SQLi
        "script", "alert", "onerror", "onload", "eval",          # XSS
        "etc/passwd", "cmd.exe", "powershell", "bin/bash",       # Command/Path traversal
        "whoami", "ping"
    ]
    count = 0
    for word in keywords:
        count += payload_lower.count(word)
    return count

def extract_features(payload):
    """Extracts features from a raw string."""
    clean_payload = payload.strip()
    features = [
        len(clean_payload),
        count_special_chars(clean_payload),
        count_keywords(clean_payload),
        round(compute_entropy(clean_payload), 3)
    ]
    return features

# Mapping to Mitre Attack Types
def map_to_mitre(payload):
    return None  # Placeholder for Mitre mapping logic  

# Main function to load model and process log file
def load_model(log_path, model_path):
    """Loads the trained model and processes the log file."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"The specified model path does not exist: {model_path}")

    if not os.path.exists(log_path):
        raise FileNotFoundError(f"The specified log path does not exist: {log_path}")

    print(f"[*] Loading trained model from {model_path}...")
    with open(model_path, 'rb') as f:
        model = pickle.load(f)

    total_lines = 0
    threats_detected = 0
    incident_reports = []

    print(f"[*] Processing log file: {log_path}...")
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue
            payload = parse_arguments(line)
            features = extract_features(payload)
            prediction = model.predict([features])[0]
            mitre_mapping = map_to_mitre(payload)
            total_lines += 1
            if prediction == 1:
                threats_detected += 1
                incident_reports.append({
                    "line": idx,
                    "payload": payload,
                    "intel": mitre_mapping
                })
            print(f"Payload: {payload}\nPrediction: {'Malicious' if prediction == 1 else 'Safe'}\nMitre Mapping: {mitre_mapping}\n")

    print(f"[*] Analysis complete.")
    print(f"Total lines processed: {total_lines}")
    print(f"Threats detected: {threats_detected}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load trained model and process log file.")
    parser.add_argument("log_path", help="Path to the log file to analyze.")
    parser.add_argument("model_path", help="Path to the trained model file (model.pkl).")
    args = parser.parse_args()

    load_model(args.log_path, args.model_path)