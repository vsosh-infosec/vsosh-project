import os, re, json, yaml, time, math, sqlite3, hashlib, subprocess
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

SCORE_MODULES = {'subprocess': 15, 'os': 10, 'socket': 15, 'ctypes': 20, 'requests': 10, 'urllib': 10, 'paramiko': 20, 'child_process': 15, 'fs': 5, 'net': 15, 'libc': 10}
SCORE_FUNCTIONS = {'system': 20, 'popen': 20, 'exec': 25, 'execSync': 25, 'eval': 25, 'connect': 15, 'bind': 15, 'spawn': 15}

MITRE_MAP = {
    ('subprocess', 'Popen'): 'T1059', ('subprocess', 'call'): 'T1059', ('subprocess', 'run'): 'T1059',
    ('os', 'system'): 'T1059', ('os', 'popen'): 'T1059', ('socket', 'connect'): 'T1071', ('socket', 'bind'): 'T1071',
    ('child_process', 'exec'): 'T1059', ('child_process', 'spawn'): 'T1059', ('net', 'connect'): 'T1071',
    ('ctypes', 'CDLL'): 'T1055', ('requests', 'get'): 'T1071.001', ('requests', 'post'): 'T1071.001'
}

SUSPICIOUS_IMPORTS = {
    'setuid': ('T1548', 30, 'Privilege escalation'), 'setreuid': ('T1548', 30, 'Privilege escalation'),
    'setgid': ('T1548', 25, 'Privilege escalation'), 'ptrace': ('T1055.008', 20, 'Process injection'),
    'system': ('T1059', 15, 'Command execution'), 'execve': ('T1059', 10, 'Program execution'),
    'popen': ('T1059', 15, 'Process pipe'), 'socket': ('T1071', 10, 'Network socket'),
    'connect': ('T1071', 10, 'Network connect'), 'bind': ('T1071', 10, 'Network bind'),
    'init_module': ('T1547.006', 25, 'Kernel module'), 'mprotect': ('T1055', 10, 'Memory protection')
}

SUSPICIOUS_STRINGS = [
    (r'api\.telegram\.org', 'T1102', 20, 'Telegram API'), (r'discord\.com', 'T1102', 15, 'Discord'),
    (r'/etc/shadow', 'T1003', 25, 'Shadow file'), (r'/etc/passwd', 'T1003', 15, 'Passwd file'),
    (r'\.ssh/', 'T1552.004', 20, 'SSH directory'), (r'LD_PRELOAD', 'T1574.006', 15, 'LD_PRELOAD'),
    (r'PTRACE_TRACEME', 'T1622', 15, 'Anti-debugging')
]

SUSPICIOUS_HOSTS = {
    'api.telegram.org': ('T1102', 20, 'Telegram Bot API'), 'discord.com': ('T1102', 15, 'Discord'),
    'pastebin.com': ('T1102', 15, 'Pastebin'), 'raw.githubusercontent.com': ('T1105', 10, 'GitHub raw'),
    'ipinfo.io': ('T1016', 10, 'IP geolocation'), 'ip-api.com': ('T1016', 10, 'IP geolocation')
}

FILE_TYPES = {'.py': 'python', '.pyw': 'python', '.js': 'javascript', '.mjs': 'javascript', '.sh': 'shell', '.bash': 'shell'}


@dataclass
class ThreatEvent:
    source: str
    event_type: str
    details: str
    score: int
    mitre: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class YaraMatch:
    rule: str
    description: str
    score: int
    mitre: str = ""
    strings: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    verdict: str
    threat_score: int
    reasons: List[str]
    events: List[ThreatEvent]
    duration: float
    file_type: str
    file_hash: str
    yara_matches: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    vm_used: bool = False


class YaraScanner:
    def __init__(self, rules_dir="yara_rules"):
        self.rules = None
        self._available = False
        try:
            import yara
            if os.path.exists(rules_dir):
                files = {f: os.path.join(rules_dir, f) for f in os.listdir(rules_dir) if f.endswith(('.yar', '.yara'))}
                if files:
                    self.rules = yara.compile(filepaths=files)
                    self._available = True
        except ImportError:
            pass

    @property
    def available(self):
        return self._available

    def scan(self, path):
        if not self._available or not os.path.exists(path):
            return []
        try:
            matches = []
            for m in self.rules.match(path):
                meta = m.meta if hasattr(m, 'meta') else {}
                matches.append(YaraMatch(
                    rule=m.rule, description=meta.get('description', m.rule),
                    score=int(meta.get('score', 10)), mitre=meta.get('mitre', ''),
                    strings=[s.identifier for s in (m.strings[:5] if hasattr(m, 'strings') else [])]
                ))
            return matches
        except:
            return []


class ELFAnalyzer:
    def __init__(self):
        self._available = False
        try:
            from elftools.elf.elffile import ELFFile
            self._available = True
        except ImportError:
            pass

    @property
    def available(self):
        return self._available

    def analyze(self, path):
        if not self._available or not os.path.exists(path):
            return []
        events = []
        try:
            from elftools.elf.elffile import ELFFile
            with open(path, 'rb') as f:
                elf = ELFFile(f)
                events.extend(self._check_imports(elf))
                f.seek(0)
                events.extend(self._check_strings(f.read()))
                events.extend(self._check_entropy(elf))
        except:
            pass
        return events

    def _check_imports(self, elf):
        events, found = [], set()
        try:
            for section in elf.iter_sections():
                if section.name == '.dynstr':
                    for s in section.data().split(b'\x00'):
                        sym = s.decode('utf-8', errors='ignore')
                        if sym in SUSPICIOUS_IMPORTS and sym not in found:
                            found.add(sym)
                            mitre, score, desc = SUSPICIOUS_IMPORTS[sym]
                            events.append(ThreatEvent('elf', 'import', f"{sym}: {desc}", score, mitre))
        except:
            pass
        return events

    def _check_strings(self, data):
        events, strings, current = [], [], []
        for b in data:
            if 32 <= b <= 126:
                current.append(chr(b))
            else:
                if len(current) >= 4:
                    strings.append(''.join(current))
                current = []
        text = '\n'.join(strings)
        for pattern, mitre, score, desc in SUSPICIOUS_STRINGS:
            if re.search(pattern, text, re.IGNORECASE):
                events.append(ThreatEvent('elf', 'string', desc, score, mitre))
        return events

    def _check_entropy(self, elf):
        events = []
        for section in elf.iter_sections():
            if section.name in ['.text', '.data']:
                try:
                    data = section.data()
                    if len(data) > 100:
                        counts = [0] * 256
                        for b in data:
                            counts[b] += 1
                        entropy = -sum(c/len(data) * math.log2(c/len(data)) for c in counts if c > 0)
                        if entropy > 7.5:
                            events.append(ThreatEvent('elf', 'entropy', f"High entropy {section.name}: {entropy:.2f}", 15, 'T1027'))
                except:
                    pass
        return events


class RuleEngine:
    def __init__(self, patterns_file="patterns.yaml"):
        self.patterns = {}
        if os.path.exists(patterns_file):
            try:
                with open(patterns_file, 'r', encoding='utf-8') as f:
                    self.patterns = yaml.safe_load(f) or {}
            except:
                pass

    def match_script(self, lang, code):
        events = []
        for cat, patterns in self.patterns.get('scripts', {}).get(lang, {}).items():
            if isinstance(patterns, list):
                for p in patterns:
                    if isinstance(p, dict) and p.get('pattern'):
                        try:
                            if re.search(p['pattern'], code):
                                events.append(ThreatEvent('script', cat, p.get('description', 'Suspicious pattern'), p.get('score', 10), p.get('mitre')))
                        except:
                            pass
        return events

    def get_threshold(self, level):
        return self.patterns.get('verdict_thresholds', {}).get(level, 50)


class ThreatScorer:
    def __init__(self, rules=None):
        self.events = []
        self.total_score = 0
        self.rules = rules or RuleEngine()

    def add_event(self, event):
        self.events.append(event)
        self.total_score += event.score

    def add_events(self, events):
        for e in events:
            self.add_event(e)

    def add_yara(self, matches):
        for m in matches:
            self.add_event(ThreatEvent('yara', 'signature', f"{m.rule}: {m.description}", m.score, m.mitre or None))

    def verdict(self):
        if self.total_score <= self.rules.get_threshold('clean'):
            return "CLEAN"
        if self.total_score <= self.rules.get_threshold('suspicious'):
            return "SUSPICIOUS"
        return "MALICIOUS"

    def reasons(self):
        return [f"[{e.source.upper()}] {e.details}" + (f" ({e.mitre})" if e.mitre else "") for e in self.events]

    def mitre_list(self):
        return list({e.mitre for e in self.events if e.mitre})


class AnalysisDB:
    def __init__(self, db_path="logs/dynamic_analysis.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS analyses (id INTEGER PRIMARY KEY AUTOINCREMENT, file_hash TEXT NOT NULL, file_name TEXT, file_type TEXT, verdict TEXT, threat_score INTEGER, duration REAL, vm_used INTEGER DEFAULT 0, reasons TEXT, yara_matches TEXT, mitre_techniques TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
            try:
                conn.execute("ALTER TABLE analyses ADD COLUMN vm_used INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass

    def save(self, path, result):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO analyses (file_hash, file_name, file_type, verdict, threat_score, duration, vm_used, reasons, yara_matches, mitre_techniques) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result.file_hash, os.path.basename(path), result.file_type, result.verdict, result.threat_score, result.duration, 1 if result.vm_used else 0, json.dumps(result.reasons), json.dumps(result.yara_matches), json.dumps(result.mitre_techniques))
            )
            return cur.lastrowid

    def get_by_hash(self, file_hash):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM analyses WHERE file_hash=? ORDER BY created_at DESC LIMIT 1", (file_hash,)).fetchone()
        if row:
            return {k: json.loads(row[k]) if k in ('reasons', 'yara_matches', 'mitre_techniques') and row[k] else row[k] for k in row.keys()}
        return None


class DynamicAnalyzer:
    def __init__(self, timeout=60, db_path="logs/dynamic_analysis.db", yara_dir="yara_rules", patterns_file="patterns.yaml", vm_config_path="vm_config.yaml"):
        self.timeout = timeout
        self.yara = YaraScanner(yara_dir)
        self.rules = RuleEngine(patterns_file)
        self.elf = ELFAnalyzer()
        self.db = AnalysisDB(db_path)
        self.vm_config_path = vm_config_path
        self._vm_manager = None
        self._vm_pool = None
        self._vm_available = False
        self._init_vm()

    def _init_vm(self):
        try:
            from vm_manager.vm_manager import VMManager
            from vm_manager.vm_pool import VMPool
            if os.path.exists(self.vm_config_path):
                self._vm_manager = VMManager(config_path=self.vm_config_path)
                self._vm_pool = VMPool(self._vm_manager)
                self._vm_available = True
        except ImportError:
            pass
        except Exception as e:
            print(f"VM init failed: {e}")

    def warmup_vms(self, blocking=True):
        if not self._vm_pool:
            return {}
        return self._vm_pool.warmup(blocking=blocking)

    @property
    def vm_pool(self):
        return self._vm_pool

    @property
    def vm_available(self):
        return self._vm_available and self._vm_manager is not None

    def _hash_file(self, path):
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return ''

    def _detect_type(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext in FILE_TYPES:
            return FILE_TYPES[ext]
        try:
            info = subprocess.run(['file', '-b', path], capture_output=True, text=True, timeout=5).stdout.lower()
            if 'elf' in info:
                if 'x86-64' in info or 'amd64' in info:
                    return 'elf_x64'
                if 'aarch64' in info or 'arm64' in info:
                    return 'elf_arm64'
                return 'elf'
            if 'python' in info:
                return 'python'
            if 'shell' in info:
                return 'shell'
        except:
            pass
        return 'unknown'

    def run(self, file_path, use_cache=True, architecture=None):
        start = time.time()
        if not os.path.exists(file_path):
            return {'verdict': 'ERROR', 'threat_score': 0, 'reasons': ['File not found']}
        file_hash = self._hash_file(file_path)
        if use_cache and file_hash:
            cached = self.db.get_by_hash(file_hash)
            if cached:
                cached['cached'] = True
                return cached
        scorer = ThreatScorer(self.rules)
        file_type = self._detect_type(file_path)
        scorer.add_yara(self.yara.scan(file_path))
        if file_type in ['python', 'javascript', 'shell']:
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    scorer.add_events(self.rules.match_script(file_type, f.read()))
            except:
                pass
        elif file_type.startswith('elf'):
            scorer.add_events(self.elf.analyze(file_path))
        sandbox_result = {}
        vm_used = False
        if self.vm_available:
            try:
                sandbox_result = self._run_in_vm(file_path, file_type, architecture)
                vm_used = True
                if sandbox_result.get('success'):
                    self._process_vm_events(scorer, sandbox_result)
            except Exception as e:
                sandbox_result = {'error': str(e), 'success': False}
        else:
            sandbox_result = {'error': 'VM not available', 'success': False}
        duration = time.time() - start
        result = AnalysisResult(
            verdict=scorer.verdict(), threat_score=min(scorer.total_score, 100), reasons=scorer.reasons(),
            events=scorer.events, duration=duration, file_type=file_type, file_hash=file_hash,
            yara_matches=[m.rule for m in self.yara.scan(file_path)], mitre_techniques=scorer.mitre_list(), vm_used=vm_used
        )
        try:
            self.db.save(file_path, result)
        except:
            pass
        return {
            'verdict': result.verdict, 'threat_score': result.threat_score, 'duration': result.duration,
            'reasons': result.reasons, 'file_type': result.file_type, 'file_hash': result.file_hash,
            'yara_matches': result.yara_matches, 'mitre_techniques': result.mitre_techniques,
            'sandbox': sandbox_result, 'event_count': len(scorer.events), 'vm_used': vm_used
        }

    def _process_vm_events(self, scorer, sandbox_result):
        for event in sandbox_result.get('syscalls', []):
            syscall = event.get('syscall', '')
            if syscall in ['execve', 'execveat']:
                scorer.add_event(ThreatEvent('vm', 'syscall', f"exec: {event.get('args', [''])[0][:100]}", 10, 'T1059'))
            elif syscall in ['connect', 'bind']:
                scorer.add_event(ThreatEvent('vm', 'syscall', f"network: {syscall}", 10, 'T1071'))
            elif syscall == 'ptrace':
                scorer.add_event(ThreatEvent('vm', 'syscall', 'ptrace call detected', 20, 'T1055.008'))
        for event in sandbox_result.get('network', []):
            dst = event.get('dst_addr', '')
            port = event.get('dst_port', 0)
            for host, (mitre, score, desc) in SUSPICIOUS_HOSTS.items():
                if host in dst:
                    scorer.add_event(ThreatEvent('vm', 'network', f"{desc}: {dst}:{port}", score, mitre))
                    break
            else:
                scorer.add_event(ThreatEvent('vm', 'network', f"connection to {dst}:{port}", 5, 'T1071'))
        for event in sandbox_result.get('files', []):
            path = event.get('path', '')
            if '/etc/shadow' in path or '/etc/passwd' in path:
                scorer.add_event(ThreatEvent('vm', 'file', f"sensitive file access: {path}", 20, 'T1003'))
            elif '/.ssh/' in path:
                scorer.add_event(ThreatEvent('vm', 'file', f"SSH directory access: {path}", 15, 'T1552.004'))

    def _run_in_vm(self, file_path, file_type, architecture=None):
        if not self._vm_manager:
            return {'error': 'VM manager not available', 'success': False}
        try:
            from vm_manager.vm_config import VMArchitecture
            if architecture:
                arch = VMArchitecture.ARM64 if 'arm' in architecture.lower() else VMArchitecture.X64
            elif file_type == 'elf_arm64':
                arch = VMArchitecture.ARM64
            elif file_type == 'elf_x64':
                arch = VMArchitecture.X64
            else:
                arch = VMArchitecture.ARM64
            if self._vm_pool and self._vm_pool.is_ready:
                result = self._vm_pool.analyze(arch, file_path, timeout=self.timeout)
            else:
                result = self._vm_manager.analyze_file(file_path, arch=arch, timeout=self.timeout)
            return {
                'success': result.success, 'error': result.error, 'duration': result.duration,
                'stdout': result.stdout, 'stderr': result.stderr, 'exit_code': result.exit_code,
                'syscalls': result.syscalls, 'network': result.network_activity,
                'files': result.file_activity, 'processes': result.process_activity,
                'events': result.events, 'architecture': result.architecture
            }
        except Exception as e:
            return {'error': str(e), 'success': False}

    def start_vm(self, architecture='arm64'):
        if not self._vm_manager:
            return False
        try:
            from vm_manager.vm_config import VMArchitecture
            arch = VMArchitecture.ARM64 if 'arm' in architecture.lower() else VMArchitecture.X64
            return self._vm_manager.start_vm(arch)
        except:
            return False

    def stop_vm(self, architecture=None):
        if not self._vm_manager:
            return
        if architecture:
            try:
                from vm_manager.vm_config import VMArchitecture
                arch = VMArchitecture.ARM64 if 'arm' in architecture.lower() else VMArchitecture.X64
                self._vm_manager.stop_vm(arch)
            except:
                pass
        else:
            self._vm_manager.stop_all()

    def get_status(self):
        status = {'yara_available': self.yara.available, 'elf_analyzer': self.elf.available, 'rules_loaded': len(self.rules.patterns) > 0, 'vm_available': self.vm_available}
        if self._vm_manager:
            try:
                vm_status = self._vm_manager.get_status()
                status['vm_arm64_running'] = vm_status.get('arm64', {}).get('running', False)
                status['vm_x64_running'] = vm_status.get('x64', {}).get('running', False)
            except:
                pass
        return status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._vm_manager:
            self._vm_manager.stop_all()


VMDynamicAnalyzer = DynamicAnalyzer
