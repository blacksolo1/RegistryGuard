import requests
import json
import argparse
import sys
import urllib3
from datetime import datetime

# Setup & Silence SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RegistryGuardPro:
    def __init__(self, target):
        self.target = target.strip().rstrip('/')
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"https://{self.target}"
        
        self.headers = {
            'User-Agent': 'RegistryGuard-Pro-Auditor/2.0',
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
        }
        self.report = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "summary": {"vulnerabilities_found": 0},
            "findings": [],
            "inventory": {}
        }

    def log_finding(self, severity, title, detail):
        self.report["summary"]["vulnerabilities_found"] += 1
        finding = {"severity": severity, "issue": title, "detail": detail}
        self.report["findings"].append(finding)
        print(f"[{severity}] {title}: {detail}")

    def run(self):
        print(f"\n{'='*60}\n[!] STARTING PROFESSIONAL REGISTRY AUDIT: {self.target}\n{'='*60}")
        
        if not self._check_v2_auth():
            print("[-] API requires authentication. Ending scan.")
            return

        self._fetch_inventory()
        self._check_write_access()
        self._export_report()

    def _check_v2_auth(self):
        try:
            r = requests.get(f"{self.target}/v2/", headers=self.headers, verify=False, timeout=10)
            if r.status_code == 200:
                self.log_finding("HIGH", "Anonymous API Access", "The V2 API is exposed without authentication.")
                return True
            return False
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False

    def _fetch_inventory(self):
        print(f"[*] Mapping repository inventory...")
        try:
            r = requests.get(f"{self.target}/v2/_catalog", headers=self.headers, verify=False)
            if r.status_code == 200:
                repos = r.json().get('repositories', [])
                self.log_finding("MEDIUM", "Information Disclosure", f"Catalog exposed. Found {len(repos)} repositories.")
                
                print(f"\n{'REPOSITORY NAME':<45} | {'TAGS'}")
                print("-" * 65)
                
                for repo in repos:
                    tags = self._fetch_tags(repo)
                    self.report["inventory"][repo] = tags
                    tag_display = ", ".join(tags[:5]) + (f" (+{len(tags)-5} more)" if len(tags) > 5 else "")
                    print(f"{repo:<45} | {tag_display if tags else 'No Tags'}")
                return repos
        except: pass
        return None

    def _fetch_tags(self, repo_name):
        try:
            r = requests.get(f"{self.target}/v2/{repo_name}/tags/list", headers=self.headers, verify=False)
            if r.status_code == 200:
                return r.json().get('tags') or []
        except: pass
        return []

    def _check_write_access(self):
        print(f"\n[*] Testing for Write/Poisoning permissions...")
        try:
            r = requests.post(f"{self.target}/v2/security_audit_test/blobs/uploads/", headers=self.headers, verify=False)
            if r.status_code in [201, 202]:
                self.log_finding("CRITICAL", "Unrestricted Write Access", "Anonymous image pushing is enabled.")
        except: pass

    def _export_report(self):
        filename = f"registry_audit_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(filename, 'w') as f:
            json.dump(self.report, f, indent=4)
        print(f"\n{'='*60}\n[+] Audit Complete. Report saved to: {filename}\n{'='*60}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RegistryGuard Pro: Professional OCI Auditor")
    parser.add_argument("-d", "--domain", help="Target Registry URL", required=True)
    args = parser.parse_args()
    RegistryGuardPro(args.domain).run()