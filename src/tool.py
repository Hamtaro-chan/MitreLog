import math
import os
import pickle
import re
import sys
import argparse
import pandas as pd

import urllib
from behavioral_analysis import BruteForceTracker
from mitreMap import map_to_mitre

# Log parser
def parse_arguments(line_args):
    match = re.search(r'"[A-Z]+\s+([^\s?]+(?:\?[^\s"]+)?)"', line_args)
    if match:
        return match.group(1)
    match_fallback = re.search(r'"[A-Z]+\s+([^\s"]+)', line_args)
    if match_fallback:
        return match_fallback.group(1)
    return line_args.strip()

def extract_ip(line_args):
    match = re.match(r'^([\d\.]+|[a-fA-F0-9:]+)', line_args)
    return match.group(1) if match else "UNKNOWN_IP"

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
        "whoami", "ping", "ls", "rm", "wget", "curl", "nc", "netcat"  # Command execution
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
    BATCH_SIZE = 50000  # Process logs in batches of 50,000 lines
    batch_features = []
    batch_metadata = []
    STATIC_EXTENSIONS = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot')

    print(f"[*] Processing log file: {log_path}...")
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        bf_tracker = BruteForceTracker(threshold=5, time_window=60)

        for idx, line in enumerate(f, start=1):
            cleaned_line = line.strip()
            if not cleaned_line:
                continue
            payload = parse_arguments(line)
            payload_lower = payload.lower()
            ip_address = extract_ip(cleaned_line)

            bf_incident = bf_tracker.evaluate_transaction(idx, ip_address, payload, cleaned_line)
            if bf_incident:
                threats_detected += 1
                incident_reports.append(bf_incident)

            if payload_lower.endswith(STATIC_EXTENSIONS):
                if "?" not in payload and "=" not in payload and "../" not in payload:
                    total_lines += 1
                    continue
            normalized_payload = urllib.parse.unquote(payload)

            features = extract_features(normalized_payload)
            length, num_special_chars, num_keywords, entropy = features
            if num_special_chars == 0 and num_keywords == 0:
                total_lines += 1
                continue

            batch_features.append(features)
            batch_metadata.append((idx, payload, cleaned_line))
            
            total_lines += 1
            if len(batch_features) >= BATCH_SIZE:
                X_df = pd.DataFrame(batch_features, columns=["length", "num_special_chars", "num_keywords", "entropy"])
                predictions = model.predict(X_df)
                for b_idx, prediction in enumerate(predictions):
                    if prediction == 1:
                        threats_detected += 1
                        line_num, raw_payload, full_line_str = batch_metadata[b_idx]
                        mitre_mapping = map_to_mitre(raw_payload)
                        incident_reports.append({
                            "line": line_num,
                            "payload": raw_payload,
                            "full_line": full_line_str,
                            "intel": mitre_mapping
                        })
                batch_features.clear()
                batch_metadata.clear()

            if total_lines % 50000 == 0:
                print(f"[*] Progress Update: Evaluated {total_lines} lines...")

    if batch_features:
            X_df = pd.DataFrame(batch_features, columns=["length", "num_special_chars", "num_keywords", "entropy"])
            predictions = model.predict(X_df)
            for b_idx, prediction in enumerate(predictions):
                if prediction == 1:
                    threats_detected += 1
                    line_num, raw_payload, full_line_str = batch_metadata[b_idx]
                    mitre_mapping = map_to_mitre(raw_payload) 
                    incident_reports.append({
                        "line": line_num,
                        "payload": raw_payload,
                        "full_line": full_line_str,
                        "intel": mitre_mapping
                    })

     # Print analysis results
    print("\n" + "="*75)
    print("         MITRELOG: INTELLIGENT THREAT DETECTION ENGINE")
    print("="*75)
    print(f" Target Resource File   : {os.path.basename(log_path)}")
    print(f" Total Log Metrics      : {total_lines} transactions evaluated")
    print(f" Threat Signatures      : {threats_detected} anomalies flagged")
    print("="*75 + "\n")
    
    if not incident_reports:
        print("[+] SUCCESS: No malicious anomalies detected within this log configuration pipeline.")
    else:
        for inc in incident_reports:
            intel = inc["intel"]
            print(f"[!] MALICIOUS ANOMALY DETECTED [Line {inc['line']}]")
            print(f"    ↳ Parsed Payload   : {inc['payload']}")
            print(f"    ↳ Full Log Line    : {inc['full_line']}")
            print(f"    ↳ Attack Profiling : {intel['attack_type']}")
            print(f"    ↳ MITRE ATT&CK     : {intel['mitre_id']} — {intel['mitre_technique']}")
            print(f"    ↳ Assigned Severity: {intel['severity']}")
            print(f"    ↳ Intel Scope      : {intel['description']}")
            print("-" * 65)
            
    print("\n" + "="*75)
    print("                   [ SECURITY ANALYSIS REPORT END ]")
    print("="*75 + "\n")

if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
    
    parser = argparse.ArgumentParser(description="MitreLog: Random Forest log threat classifier engine mapped to the MITRE ATT&CK framework.")
    parser.add_argument("--log", dest="log_path", help="Path to the log file to analyze.")
    parser.add_argument("--model", dest="model_path", help="Path to the trained model file (model.pkl).", default=DEFAULT_MODEL_PATH)
    args = parser.parse_args()

    load_model(args.log_path, args.model_path)