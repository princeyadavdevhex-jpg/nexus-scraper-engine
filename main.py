import os
import json
import time
from datetime import datetime
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from huggingface_hub import HfApi
from github import Github
from scrapegraphai.graphs import SmartScraperGraph
import nest_asyncio

nest_asyncio.apply()

# ==========================================
# ⚙️ 1. SECRETS & CONFIGURATION
# ==========================================
HF_TOKEN = os.environ.get("HF_TOKEN")
HF_REPO_ID = "prince-yadav-dev-hex/nexus-intel-vault" # Tera HF Vault

GH_PAT = os.environ.get("GH_PAT") # GitHub Personal Access Token (Private Repo access ke liye)
GH_PRIVATE_REPO = "prince-yadav-dev-hex/nexus-private-logs" # Tera naya Private GitHub Repo jahan light data jayega

GROQ_KEYS = [os.environ.get("GROQ_KEY_1"), os.environ.get("GROQ_KEY_2")]
GROQ_KEYS = [k for k in GROQ_KEYS if k] 

# ==========================================
# 📅 2. 50+ TARGET WEBSITES (7-DAY ROTATION)
# ==========================================
# Har din ke liye alag targets taaki IP/API limit na ude.
TARGET_SITES = {
    0: { # Monday: Core Vulnerability Databases
        "NVD_NIST": "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&startIndex=0",
        "CVE_Mitre": "https://cve.mitre.org/cve/search_cve_list.html",
        "CISA_KEV": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "VulnDB": "https://vulndb.cyberriskanalytics.com/",
        "Rapid7_DB": "https://www.rapid7.com/db/",
        "Tenable_Plugins": "https://www.tenable.com/plugins",
        "Qualys_Threat": "https://threatprotect.qualys.com/",
        "IBM_XForce": "https://exchange.xforce.ibmcloud.com/"
    },
    1: { # Tuesday: Exploit & Zero-Day Markets
        "Exploit_DB": "https://www.exploit-db.com/",
        "PacketStorm": "https://packetstormsecurity.com/files/tags/exploit/",
        "CXSecurity": "https://cxsecurity.com/exploit/",
        "0day_Today": "https://0day.today/",
        "ZeroDayInitiative": "https://www.zerodayinitiative.com/advisories/published/",
        "Vuln_Lab": "https://www.vulnlab.com/",
        "SecLists": "https://seclists.org/fulldisclosure/",
        "Exploit_Alert": "https://www.exploitalert.com/"
    },
    2: { # Wednesday: Web & Developer Platforms
        "GitHub_Advisories": "https://github.com/advisories",
        "StackOverflow_Sec": "https://stackoverflow.com/questions/tagged/security",
        "WP_Scan": "https://wpscan.com/vulnerabilities",
        "Patchstack": "https://patchstack.com/database/",
        "Snyk_DB": "https://security.snyk.io/",
        "Mend_Vulnerability": "https://www.mend.io/vulnerability-database/",
        "GitLab_Advisories": "https://gitlab.com/gitlab-org/advisories-community",
        "NPM_Advisories": "https://www.npmjs.com/advisories"
    },
    3: { # Thursday: Bug Bounty & Reports
        "HackerOne_Hacktivity": "https://hackerone.com/hacktivity",
        "Bugcrowd_Crowdstream": "https://bugcrowd.com/crowdstream",
        "Intigriti_News": "https://blog.intigriti.com/category/bug-bounty/",
        "YesWeHack": "https://blog.yeswehack.com/",
        "Synack_Red_Team": "https://www.synack.com/blog/",
        "OpenBugBounty": "https://www.openbugbounty.org/",
        "Detectify_Blog": "https://blog.detectify.com/",
        "Cobalt_Core": "https://cobalt.io/blog"
    },
    4: { # Friday: Threat Intel & News
        "TheHackerNews": "https://thehackernews.com/",
        "BleepingComputer": "https://www.bleepingcomputer.com/",
        "DarkReading": "https://www.darkreading.com/vulnerabilities-threats",
        "ThreatPost": "https://threatpost.com/category/vulnerabilities/",
        "KrebsOnSecurity": "https://krebsonsecurity.com/",
        "SecurityWeek": "https://www.securityweek.com/virus-threats/",
        "CyberScoop": "https://www.cyberscoop.com/",
        "Infosec_Magazine": "https://www.infosecurity-magazine.com/"
    },
    5: { # Saturday: Deep Research & Archives
        "Wikipedia_Cyberattacks": "https://en.wikipedia.org/wiki/List_of_cyberattacks",
        "Wikipedia_Malware": "https://en.wikipedia.org/wiki/List_of_computer_viruses",
        "Google_Project_Zero": "https://googleprojectzero.blogspot.com/",
        "Talos_Intelligence": "https://blog.talosintelligence.com/",
        "Mandiant_Threat": "https://www.mandiant.com/resources/blog",
        "Kaspersky_Securelist": "https://securelist.com/",
        "PaloAlto_Unit42": "https://unit42.paloaltonetworks.com/",
        "Fortinet_FortiGuard": "https://www.fortinet.com/blog/threat-research"
    },
    6: { # Sunday: Hardware & OS Specific (Weekly Update Focus)
        "Microsoft_MSRC": "https://msrc.microsoft.com/update-guide/",
        "Apple_Security": "https://support.apple.com/en-us/HT201222",
        "Linux_Kernel_Cves": "https://www.linuxkernelcves.com/cves",
        "Ubuntu_Security": "https://ubuntu.com/security/notices",
        "RedHat_Advisories": "https://access.redhat.com/security/security-updates/",
        "Android_Security": "https://source.android.com/security/bulletin",
        "Cisco_Advisories": "https://tools.cisco.com/security/center/publicationListing.x",
        "Intel_Security": "https://www.intel.com/content/www/us/en/security-center/default.html"
    }
}

# ==========================================
# 🗄️ 3. RED DATABASE & INDEX MANAGEMENT
# ==========================================
MASTER_INDEX_FILE = "src/master_cve_index.json"
RED_DATABASE_FILE = "src/red_database_rules.json"

def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return [] if "index" in file_path else {}

def save_json(file_path, data):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

# ==========================================
# 🕷️ 4. SCRAPING LOGIC (RED DATABASE + AI FALLBACK)
# ==========================================
def fetch_clean_html(url):
    print(f"[*] Stealth Mode: Fetching {url}...")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={'width': 1280, 'height': 800})
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(3000) 
            raw_html = page.content()
            browser.close()
            
            soup = BeautifulSoup(raw_html, 'lxml')
            for tag in soup.find_all(["script", "style", "svg", "nav", "footer"]):
                tag.decompose()
            return soup
    except Exception as e:
        print(f"[!] Browser Error on {url}: {e}")
        return None

def heuristic_scrape(soup, domain, red_db):
    """Bina AI ke, Red Database rules se data nikalne ki koshish"""
    rules = red_db.get(domain)
    if not rules:
        return []
        
    extracted_data = []
    # Basic attempt to extract based on stored class names/tags
    # Note: Real static scraping requires complex regex/selectors.
    # We simulate the fallback here. If it extracts 0, it auto-triggers AI.
    items = soup.select(rules.get("item_container", "div.vuln-item"))
    for item in items:
        title = item.select_one(rules.get("title_selector", "h2"))
        desc = item.select_one(rules.get("desc_selector", "p"))
        if title and desc:
            extracted_data.append({
                "title": title.text.strip(),
                "description": desc.text.strip(),
                "attack_logic": "Static Extracted. Deep AI analysis pending.",
                "attack_code": "# Fallback attack code\npass",
                "defense_logic": "Static Extracted. Deep AI patch pending.",
                "defense_code": "# Fallback defense code\npass"
            })
    return extracted_data

def process_with_ai(html_content, domain, key_index=0):
    """Groq AI ka use karke deep intelligence nikalna"""
    if key_index >= len(GROQ_KEYS):
        print("[!] All Groq API Keys exhausted!")
        return None
        
    print(f"[*] AI Fallback Activated for {domain} (Using Key {key_index + 1})...")
    prompt = f"""
    You are an elite cybersecurity threat analyst. Extract up to 3 critical vulnerabilities from this HTML belonging to {domain}.
    Strictly provide an array of JSON objects with these exact keys:
    1. title: Bug Name or CVE ID (e.g., CVE-2026-1234).
    2. description: Summary of the bug.
    3. attack_logic: Detailed offensive explanation of the exploit.
    4. attack_code: Actionable bash/python/C++ payload snippet.
    5. defense_logic: Detailed defensive patching strategy.
    6. defense_code: Secure code implementation snippet.
    """
    
    try:
        config = {
            "llm": {"api_key": GROQ_KEYS[key_index], "model": "groq/llama-3.1-8b-instant"},
            "verbose": False
        }
        scraper = SmartScraperGraph(prompt=prompt, source=str(html_content), config=config)
        return scraper.run()
    except Exception as e:
        if "429" in str(e):
            print(f"[!] Rate Limit hit. Rotating Groq Key...")
            return process_with_ai(html_content, domain, key_index + 1)
        else:
            print(f"[!] AI Error: {e}")
            return None

# ==========================================
# ☁️ 5. MULTI-VAULT STORAGE (HF + PRIVATE GITHUB)
# ==========================================
def push_intel_to_private_github(intel_data, repo_path):
    """Sirf light data (AI Summary) Private GitHub repo mein bhejega"""
    if not GH_PAT:
        print("[!] GitHub PAT not found. Skipping Private Repo push.")
        return
        
    try:
        g = Github(GH_PAT)
        repo = g.get_repo(GH_PRIVATE_REPO)
        commit_message = f"⚡ Nexus Vault Intel: {intel_data['title']}"
        
        # Check if file exists to update, else create
        try:
            contents = repo.get_contents(repo_path)
            repo.update_file(contents.path, commit_message, json.dumps(intel_data, indent=4), contents.sha)
        except:
            repo.create_file(repo_path, commit_message, json.dumps(intel_data, indent=4))
        print(f"  [+] Light Intel synced to Private GitHub: {repo_path}")
    except Exception as e:
        print(f"  [!] GitHub Push Error: {e}")

def save_and_route_data(item, domain):
    """Strict Folder Structure: Month_Year / DD_Month / Domain / Bug_ID / files"""
    cve_id = item.get("title", "Unknown").replace(":", "_").replace(" ", "_").replace("/", "_").strip()
    
    now = datetime.now()
    month_year = now.strftime("%B_%Y")   # e.g., May_2026
    date_month = now.strftime("%d_%B")   # e.g., 13_May
    
    # HF Route Path
    hf_base_path = f"{month_year}/{date_month}/{domain}/{cve_id}"
    local_base_path = f"src/vault/{hf_base_path}"
    os.makedirs(local_base_path, exist_ok=True)
    
    # 1. Prepare Files
    intel_content = {
        "title": cve_id, 
        "domain_source": domain,
        "description": item.get("description"),
        "offensive_summary": item.get("attack_logic")[:150] + "...", # Very brief for Github limits
        "defensive_summary": item.get("defense_logic")[:150] + "..."
    }
    exploit_content = {"logic": item.get("attack_logic"), "code": item.get("attack_code")}
    patch_content = {"logic": item.get("defense_logic"), "code": item.get("defense_code")}
    
    files = {
        "intel.json": intel_content,
        "exploit.json": exploit_content,
        "patch.json": patch_content
    }
    
    api = HfApi()
    for name, content in files.items():
        file_path = f"{local_base_path}/{name}"
        with open(file_path, "w") as f:
            json.dump(content, f, indent=4)
            
        # PUSH HEAVY DATA TO HUGGING FACE
        hf_destination = f"{hf_base_path}/{name}"
        try:
            api.upload_file(
                path_or_fileobj=file_path,
                path_in_repo=hf_destination,
                repo_id=HF_REPO_ID,
                repo_type="dataset",
                token=HF_TOKEN
            )
        except Exception as e:
            print(f"  [!] HF Upload Error for {name}: {e}")
            
    # PUSH LIGHT DATA TO PRIVATE GITHUB REPO
    gh_path = f"{hf_base_path}/intel.json"
    push_intel_to_private_github(intel_content, gh_path)

# ==========================================
# 🚀 6. MAIN EXECUTION FLOW
# ==========================================
def main():
    print(f"=== NEXUS DEEP INTEL ENGINE v4.0 (Red Database Edition) ===")
    
    today_num = datetime.today().weekday()
    # FORCE AI REFRESH EVERY SUNDAY (Day 6)
    is_weekly_ai_update_day = (today_num == 6) 
    
    target_dict = TARGET_SITES.get(today_num, {})
    master_index = load_json(MASTER_INDEX_FILE)
    red_db = load_json(RED_DATABASE_FILE)
    
    print(f"[*] Day {today_num}: Targetting {len(target_dict)} Domains.")
    if is_weekly_ai_update_day:
        print("[!] WEEKLY RED-DATABASE UPDATE OVERRIDE (Forcing AI Analysis)")

    for domain, url in target_dict.items():
        print(f"\n--- Initiating Breach Sequence: {domain} ---")
        soup = fetch_clean_html(url)
        if not soup:
            continue
            
        vulnerabilities = []
        
        # Step 1: Static Heuristic Fallback (Red Database)
        if not is_weekly_ai_update_day:
            vulnerabilities = heuristic_scrape(soup, domain, red_db)
            if vulnerabilities:
                print(f"[*] Successfully extracted {len(vulnerabilities)} bugs using Red Database.")
        
        # Step 2: AI Fallback (If Static fails or Weekly Update)
        if not vulnerabilities:
            ai_result = process_with_ai(soup, domain)
            if ai_result:
                vulnerabilities = ai_result.get("vulnerabilities", []) if isinstance(ai_result, dict) else ai_result
                # We update Red Database flag to show AI was needed today
                red_db[domain] = {"status": "AI_Processed", "last_update": datetime.now().isoformat()}

        if not isinstance(vulnerabilities, list) or len(vulnerabilities) == 0:
            print(f"[-] No actionable intel found for {domain} today.")
            continue

        # Step 3: Deduplication & Storage Routing
        added_count = 0
        for item in vulnerabilities:
            cve_id = item.get("title", "Unknown").strip()
            
            if cve_id in master_index or len(cve_id) < 4:
                continue
                
            print(f"[*] Routing Intel: {cve_id} -> HF Vault & Private Repo")
            save_and_route_data(item, domain)
            master_index.append(cve_id)
            added_count += 1
            time.sleep(2) # Respect API limits
            
        print(f"[+] Synced {added_count} new Zero-Days from {domain}.")
        
    # Save the states locally for GitHub Action to commit to public runner repo
    save_json(MASTER_INDEX_FILE, master_index)
    save_json(RED_DATABASE_FILE, red_db)
    print("\n[SUCCESS] Nexus Daily Operations Concluded.")

if __name__ == "__main__":
    main()

