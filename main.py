import os
import json
import time
from datetime import datetime
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from huggingface_hub import HfApi
from scrapegraphai.graphs import SmartScraperGraph

# ==========================================
# ⚙️ CONFIGURATION (Bas ise check kar lena)
# ==========================================
HF_TOKEN = os.environ.get("HF_TOKEN")
# TERA HUGGING FACE REPO ID (Username/Dataset-Name)
HF_REPO_ID = "prince-yadav-dev-hex/nexus-intel-vault" 
GROQ_KEYS = [os.environ.get("GROQ_KEY_1"), os.environ.get("GROQ_KEY_2")]
GROQ_KEYS = [k for k in GROQ_KEYS if k] # Filter out empty keys

TARGET_URL = "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&results_type=overview&form_type=Basic&search_type=all&startIndex=0"
INDEX_FILE = "master_cve_index.json"

def load_master_index():
    if os.path.exists(INDEX_FILE):
        with open(INDEX_FILE, "r") as f:
            return json.load(f)
    return []

def save_master_index(data):
    with open(INDEX_FILE, "w") as f:
        json.dump(data, f, indent=4)

def fetch_clean_html(url):
    print(f"[*] Stealth Mode: Fetching NVD Database...")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={'width': 1280, 'height': 800})
            page = context.new_page()
            
            page.goto(url, wait_until="networkidle", timeout=60000)
            print("[*] Waiting for vulnerability table to load...")
            page.wait_for_selector("table.table-striped", state="visible", timeout=30000)
            page.wait_for_timeout(2000) 
            
            raw_html = page.content()
            browser.close()
            
            soup = BeautifulSoup(raw_html, 'lxml')
            for tag in soup.find_all(["script", "style", "svg", "nav", "footer", "header"]):
                tag.decompose()
            return soup.prettify()
    except Exception as e:
        print(f"[!] Browser Error: {e}")
        return None

def process_with_ai(html_content, key_index=0):
    if key_index >= len(GROQ_KEYS):
        print("[!] All Groq API Keys exhausted!")
        return None
        
    print(f"[*] Analyzing with AI (Using Key {key_index + 1})...")
    prompt = """
    Extract a list of top 5 most critical vulnerabilities from this HTML.
    For each, strictly provide:
    1. title: The CVE ID (e.g., CVE-2026-1234).
    2. description: Summary of the bug.
    3. attack_logic: Brief technical explanation on how an attacker exploits this.
    4. attack_code: A short python or bash pseudo-code snippet showing the attack.
    5. defense_logic: How to patch or prevent this.
    6. defense_code: A short code snippet showing the fix or secure implementation.
    """
    
    try:
        config = {
            "llm": {"api_key": GROQ_KEYS[key_index], "model": "groq/llama-3.1-8b-instant"},
            "verbose": True
        }
        scraper = SmartScraperGraph(prompt=prompt, source=html_content, config=config)
        return scraper.run()
    except Exception as e:
        if "429" in str(e):
            print(f"[!] Rate Limit hit on Key {key_index + 1}. Rotating to next key...")
            return process_with_ai(html_content, key_index + 1)
        else:
            print(f"[!] AI Processing Error: {e}")
            return None

def save_and_push_to_hf(item):
    cve_id = item.get("title", "Unknown").replace(":", "_").strip()
    base_date = datetime.now().strftime("%B_%Y/%d_%B")
    local_path = f"src/vault/{base_date}/{cve_id}"
    os.makedirs(local_path, exist_ok=True)
    
    # 1. Prepare Files
    files = {
        "intel.json": {"title": cve_id, "desc": item.get("description")},
        "exploit.json": {"logic": item.get("attack_logic"), "code": item.get("attack_code")},
        "patch.json": {"logic": item.get("defense_logic"), "code": item.get("defense_code")}
    }
    
    # 2. Save Locally & Push to HF
    api = HfApi()
    for name, content in files.items():
        file_path = f"{local_path}/{name}"
        with open(file_path, "w") as f:
            json.dump(content, f, indent=4)
            
        hf_path = f"{base_date}/{cve_id}/{name}"
        try:
            api.upload_file(
                path_or_fileobj=file_path,
                path_in_repo=hf_path,
                repo_id=HF_REPO_ID,
                repo_type="dataset",
                token=HF_TOKEN
            )
            print(f"  [+] Uploaded {hf_path} to Hugging Face!")
        except Exception as e:
            print(f"  [!] Hugging Face upload failed for {cve_id}: {e}")

def main():
    print(f"=== NEXUS DEEP INTEL ENGINE v3.0 ===")
    html = fetch_clean_html(TARGET_URL)
    if not html:
        return
        
    ai_result = process_with_ai(html)
    if not ai_result:
        return
        
    vulnerabilities = ai_result.get("vulnerabilities", []) if isinstance(ai_result, dict) else ai_result
    
    if not isinstance(vulnerabilities, list):
        print("[!] Unexpected AI output format.")
        return

    master_index = load_master_index()
    new_cves_added = 0
    
    for item in vulnerabilities:
        cve_id = item.get("title", "Unknown").strip()
        
        # Deduplication Check
        if cve_id in master_index:
            print(f"[-] Skipping {cve_id} (Already in Vault)")
            continue
            
        print(f"[*] Processing New Intel: {cve_id}")
        save_and_push_to_hf(item)
        
        master_index.append(cve_id)
        new_cves_added += 1
        time.sleep(1) # Chota sa pause taaki HF API gussa na ho
        
    if new_cves_added > 0:
        save_master_index(master_index)
        print(f"\n[SUCCESS] Added {new_cves_added} new Zero-Days to the Nexus Vault!")
    else:
        print("\n[INFO] No new vulnerabilities found today.")

if __name__ == "__main__":
    main()

