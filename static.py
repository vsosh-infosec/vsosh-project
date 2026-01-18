import os, re, hashlib, subprocess
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None

try:
    import yaml
except ImportError:
    yaml = None

from dynamic import YaraScanner, YaraMatch

SUSPICIOUS_IMPORTS = {
    'python': ['subprocess', 'socket', 'ctypes', 'requests', 'urllib', 'paramiko',
               'ftplib', 'smtplib', 'eval', 'exec', 'pickle', 'base64', 'cryptography',
               'pyautogui', 'pynput', 'win32api', 'winreg', 'psutil'],
    'javascript': ['child_process', 'net', 'fs', 'http', 'https', 'crypto', 'os',
                   'vm', 'cluster', 'dns', 'tls', 'puppeteer', 'selenium-webdriver']
}
EXT_LANG = {'.py': 'python', '.pyw': 'python', '.js': 'javascript', '.mjs': 'javascript'}


class ClamAVScanner:
    def __init__(self, bin_path: str = "clamscan"):
        self.bin = bin_path
        try:
            self._available = subprocess.run(['which', bin_path], capture_output=True, timeout=5).returncode == 0
        except:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def scan(self, path: str) -> Dict:
        if not self._available:
            return {"infected": False, "signature": None}
        try:
            r = subprocess.run([self.bin, '--no-summary', path], capture_output=True, text=True, timeout=60)
            infected = r.returncode == 1
            sig = None
            if infected:
                for line in r.stdout.split('\n'):
                    if 'FOUND' in line:
                        sig = line.split(':')[-1].replace(' FOUND', '').strip()
                        break
            return {"infected": infected, "signature": sig}
        except:
            return {"infected": False, "signature": None}


class VirusTotalChecker:
    API_URL = "https://www.virustotal.com/api/v3/files/{hash}"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 25):
        self.api_key = api_key or os.environ.get('VIRUSTOTAL_API_KEY', '')
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key) and requests is not None

    def check_hash(self, file_hash: str) -> Dict:
        if not self.available or len(file_hash) < 32:
            return {"found": False, "malicious": 0}
        try:
            r = requests.get(self.API_URL.format(hash=file_hash),
                           headers={"x-apikey": self.api_key}, timeout=self.timeout)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {"found": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
            return {"found": False, "malicious": 0}
        except:
            return {"found": False, "malicious": 0}


class ImportAnalyzer:
    def analyze_file(self, path: str) -> List[str]:
        ext = os.path.splitext(path)[1].lower()
        lang = EXT_LANG.get(ext)
        if not lang:
            return []
        try:
            with open(path, 'r', errors='ignore') as f:
                code = f.read()
            return [imp for imp in SUSPICIOUS_IMPORTS.get(lang, []) if re.search(rf'\b{re.escape(imp)}\b', code)]
        except:
            return []


class StaticAnalyzer:
    def __init__(self, yara_dir: str = "yara_rules", vt_key: Optional[str] = None,
                 clamscan: str = "clamscan", config_path: Optional[str] = None):
        cfg = {}
        if config_path and yaml and os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = yaml.safe_load(f).get('static', {})
            except:
                pass
        self.yara = YaraScanner(cfg.get('yara_rules_dir', yara_dir))
        self.clamav = ClamAVScanner(cfg.get('clamscan_bin', clamscan))
        self.vt = VirusTotalChecker(cfg.get('virustotal_api_key', vt_key))
        self.imports = ImportAnalyzer()
        self.thresholds = cfg.get('verdict', {'clean': 15, 'suspicious': 30})

    def _hash(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return ''

    def run(self, path: str) -> Dict:
        if not os.path.exists(path):
            return {"verdict": "ERROR", "score": 0, "error": "File not found"}
        file_hash = self._hash(path)
        yara_matches = self.yara.scan(path)
        clamav = self.clamav.scan(path)
        vt = self.vt.check_hash(file_hash)
        imports = self.imports.analyze_file(path)
        yara_score = sum(getattr(m, 'score', 10) for m in yara_matches)
        score = yara_score
        if clamav.get('infected'):
            score += 30
        if vt.get('found'):
            mal = vt.get('malicious', 0)
            score += 25 if mal > 5 else 15 if mal >= 1 else 0
        score += len(imports) * 5
        verdict = "CLEAN" if score < self.thresholds.get('clean', 15) else \
                  "SUSPICIOUS" if score < self.thresholds.get('suspicious', 30) else "MALICIOUS"
        return {
            "verdict": verdict, "score": score, "hash": file_hash,
            "yara_matches": [m.rule for m in yara_matches],
            "clamav": clamav, "virustotal": vt, "suspicious_imports": imports
        }

    def get_status(self) -> Dict:
        return {"yara": self.yara.available, "clamav": self.clamav.available, "virustotal": self.vt.available}
