import requests
import time
import json

API_KEY = '<Your_API_Key'  # Replace with your real VirusTotal API key

# ANSI escape codes for colored output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

with open("hash.txt") as hash_file, open("analysis.txt", "w") as analysis_file:  #Need to create 2 files analysis.txt (for output) and hash.txt (add the hashes here)
    analysis_file.write("Hash\t\t\t\t# of engines detected\n")
    analysis_file.write("========================================================\n\n")

    count = 0
    for hashn in hash_file:
        hashn = hashn.strip()
        if not hashn:
            continue

        print(f"[{count + 1}] Checking hash: {hashn}")
        params = {'apikey': API_KEY, 'resource': hashn}

        try:
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            print(f"→ Status code: {response.status_code}")

            # Try parsing JSON response
            try:
                result = response.json()
            except json.JSONDecodeError:
                print(f"{YELLOW}→ Invalid JSON returned. Possible rate limit or bad request.{RESET}")
                print("→ Raw response:", response.text[:200])  # Print first 200 characters
                continue

            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                analysis_file.write(f"{hashn}\t\t\t{positives}\n")
                if positives > 0:
                    print(f"{RED}→ Malicious Detected! Detections: {positives}{RESET}")
                else:
                    print(f"{GREEN}→ Clean (0 detections){RESET}")
            else:
                print(f"{YELLOW}→ No report found for hash: {hashn}{RESET}")

        except Exception as e:
            print(f"{YELLOW}Error occurred: {e}. Possibly rate limit hit. Sleeping...{RESET}")

        count += 1
        if count >= 500:
            print("→ Reached daily limit of 500. Stopping.")
            break

        time.sleep(15)  # Respect VirusTotal's free API rate limit
