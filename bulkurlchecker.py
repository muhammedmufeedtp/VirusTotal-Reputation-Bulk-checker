import requests
import time
import json

API_KEY = '<Your_API_Key'  # Replace with your real VirusTotal API key

# ANSI escape codes for colored output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

with open("urls.txt") as url_file, open("url_analysis.txt", "w") as analysis_file: #Need to create 2 files url_analysis.txt (for output) and urls.txt (add the urls here)
    analysis_file.write("URL\t\t\t\t# of engines detected\n")
    analysis_file.write("========================================================\n\n")

    count = 0
    for url in url_file:
        url = url.strip()
        if not url:
            continue

        print(f"[{count + 1}] Checking URL: {url}")
        params = {'apikey': API_KEY, 'resource': url}

        try:
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params)
            print(f"→ Status code: {response.status_code}")

            try:
                result = response.json()
            except json.JSONDecodeError:
                print(f"{YELLOW}→ Invalid JSON returned. Possible rate limit or malformed URL.{RESET}")
                print("→ Raw response:", response.text[:200])
                continue

            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                analysis_file.write(f"{url}\t\t\t{positives}\n")
                if positives > 0:
                    print(f"{RED}→ Malicious Detected! Detections: {positives}{RESET}")
                else:
                    print(f"{GREEN}→ Clean (0 detections){RESET}")
            else:
                print(f"{YELLOW}→ No report found for URL: {url}{RESET}")

        except Exception as e:
            print(f"{YELLOW}Error occurred: {e}. Possibly rate limit hit. Sleeping...{RESET}")

        count += 1
        if count >= 500:
            print("→ Reached daily limit of 500. Stopping.")
            break

        # Respect rate limit (4 per minute = 1 every 15 seconds)
        time.sleep(15)
