import os
import random
import sqlite3
import time
from typing import List, Optional
from dataclasses import dataclass
from pathlib import Path

@dataclass
class ArtifactsConfig:
    home_dir: str = "/home/user"
    num_documents: int = 20
    num_pictures: int = 17
    num_downloads: int = 10
    num_history_entries: int = 100
    date_range_days: int = 90
    bash_history: bool = True
    browser_history: bool = True

COMMON_URLS = [
    ("https://www.google.com/", "Google"), ("https://www.youtube.com/", "YouTube"),
    ("https://www.facebook.com/", "Facebook"), ("https://twitter.com/", "X"),
    ("https://www.reddit.com/", "Reddit"), ("https://www.amazon.com/", "Amazon"),
    ("https://github.com/", "GitHub"), ("https://stackoverflow.com/", "Stack Overflow"),
    ("https://mail.google.com/", "Gmail"), ("https://www.netflix.com/", "Netflix"),
    ("https://discord.com/", "Discord"), ("https://www.bbc.com/news", "BBC News"),
    ("https://maps.google.com/", "Google Maps"), ("https://drive.google.com/", "Google Drive"),
]

BASH_CMDS = [
    "ls -la", "cd Documents", "cd Downloads", "pwd", "cat file.txt", "vim config.yaml",
    "python3 script.py", "pip install requests", "git status", "git pull", "git push",
    "sudo apt update", "df -h", "free -m", "htop", "ps aux", "grep -r 'error' logs/",
    "tar -xvf archive.tar.gz", "wget https://example.com/file", "ssh user@server", "chmod +x script.sh",
    "npm install", "docker ps", "history", "clear", "exit"
]

DOC_TEMPLATES = {
    'report.docx': b'PK\x03\x04' + b'\x00' * 100,
    'budget.xlsx': b'PK\x03\x04' + b'\x00' * 100,
    'notes.txt': b'Meeting notes\n\n- Discussed project timeline\n- Budget review\n',
    'todo.txt': b'TODO List\n\n[ ] Complete report\n[x] Send email\n',
}

JPEG_HEADER = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08] + [0x06] * 40 + [0xFF, 0xD9])

class ArtifactsGenerator:
    def __init__(self, config: Optional[ArtifactsConfig] = None):
        self.config = config or ArtifactsConfig()
    
    def generate_all(self):
        self._create_dirs()
        self._gen_documents()
        self._gen_pictures()
        self._gen_downloads()
        if self.config.bash_history:
            self._gen_bash_history()
        if self.config.browser_history:
            self._gen_browser_history()
    
    def _create_dirs(self):
        home = Path(self.config.home_dir)
        for d in ["Documents", "Documents/Work", "Documents/Personal", "Downloads", "Pictures", "Pictures/Vacation", "Pictures/Screenshots", "Videos", "Music", "Desktop", ".config/chromium/Default", ".config/google-chrome/Default", ".local/share/applications", ".cache"]:
            (home / d).mkdir(parents=True, exist_ok=True)
    
    def _write_file(self, path: Path, content: bytes):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        t = time.time() - random.randint(0, self.config.date_range_days * 86400)
        os.utime(path, (t, t))
    
    def _gen_documents(self):
        home = Path(self.config.home_dir)
        for name, content in [("quarterly_report_2024.docx", DOC_TEMPLATES['report.docx']), ("budget_2024.xlsx", DOC_TEMPLATES['budget.xlsx']), ("meeting_notes.txt", DOC_TEMPLATES['notes.txt'])]:
            self._write_file(home / "Documents/Work" / name, content)
        for name, content in [("recipes.txt", b"Chocolate Cake Recipe\n\nIngredients:\n- 2 cups flour\n"), ("shopping_list.txt", b"Shopping List\n\n- Milk\n- Bread\n")]:
            self._write_file(home / "Documents/Personal" / name, content)
    
    def _gen_pictures(self):
        home = Path(self.config.home_dir)
        for i in range(min(5, self.config.num_pictures)):
            self._write_file(home / f"Pictures/Vacation/IMG_{20230801 + i}.jpg", JPEG_HEADER)
        for i in range(3):
            self._write_file(home / f"Pictures/Screenshots/Screenshot_{20240101 + i}.png", b'\x89PNG\r\n\x1a\n' + b'\x00' * 50)
    
    def _gen_downloads(self):
        home = Path(self.config.home_dir)
        for name, content in [("installer.exe", b'MZ' + b'\x00' * 100), ("document.pdf", b'%PDF-1.4\n' + b'\x00' * 100), ("archive.zip", b'PK\x03\x04' + b'\x00' * 100), ("data.csv", b'name,value,date\ntest,123,2024-01-01\n')]:
            self._write_file(home / "Downloads" / name, content)
    
    def _gen_bash_history(self):
        home = Path(self.config.home_dir)
        hf = home / ".bash_history"
        hf.write_text('\n'.join(random.choice(BASH_CMDS) for _ in range(200)) + '\n')
        t = time.time() - random.randint(0, self.config.date_range_days * 86400)
        os.utime(hf, (t, t))
    
    def _gen_browser_history(self):
        home = Path(self.config.home_dir)
        for browser in [".config/chromium/Default", ".config/google-chrome/Default"]:
            db = home / browser / "History"
            db.parent.mkdir(parents=True, exist_ok=True)
            self._create_chrome_history(db)
    
    def _create_chrome_history(self, db_path: Path):
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER DEFAULT 1, last_visit_time INTEGER)")
        c.execute("CREATE TABLE IF NOT EXISTS visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, visit_duration INTEGER DEFAULT 0)")
        c.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        c.execute("INSERT OR REPLACE INTO meta VALUES ('version', '48')")
        
        now = time.time()
        for i in range(self.config.num_history_entries):
            url, title = random.choice(COMMON_URLS)
            vt = int((now - random.randint(0, self.config.date_range_days * 86400) + 11644473600) * 1000000)
            c.execute("INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)", (url, title, random.randint(1, 20), vt))
            c.execute("INSERT INTO visits (url, visit_time, visit_duration) VALUES (?, ?, ?)", (c.lastrowid, vt, random.randint(1000, 300000)))
        conn.commit()
        conn.close()

def generate_user_artifacts(home_dir: str = "/home/user", num_history: int = 100) -> ArtifactsGenerator:
    g = ArtifactsGenerator(ArtifactsConfig(home_dir=home_dir, num_history_entries=num_history))
    g.generate_all()
    return g
