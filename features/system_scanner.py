"""
SilentSeal - Full System Scanner
Recursive directory scanning with data inventory and progress tracking
"""

import os
import threading
import time
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional, Generator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib


class ScanStatus(Enum):
    """Scan status states"""
    IDLE = "idle"
    SCANNING = "scanning"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass
class ScanProgress:
    """Track scan progress"""
    status: ScanStatus = ScanStatus.IDLE
    total_files: int = 0
    files_scanned: int = 0
    files_with_pii: int = 0
    high_risk_files: int = 0
    medium_risk_files: int = 0
    low_risk_files: int = 0
    current_directory: str = ""
    current_file: str = ""
    start_time: float = 0
    elapsed_time: float = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def progress_percent(self) -> float:
        if self.total_files == 0:
            return 0
        return (self.files_scanned / self.total_files) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "total_files": self.total_files,
            "files_scanned": self.files_scanned,
            "files_with_pii": self.files_with_pii,
            "high_risk_files": self.high_risk_files,
            "medium_risk_files": self.medium_risk_files,
            "low_risk_files": self.low_risk_files,
            "progress_percent": round(self.progress_percent, 1),
            "current_directory": self.current_directory,
            "current_file": self.current_file,
            "elapsed_seconds": round(self.elapsed_time, 1),
            "errors_count": len(self.errors)
        }


@dataclass
class ScannedFile:
    """Represents a scanned file with PII info"""
    file_path: str
    file_name: str
    file_size: int
    file_hash: str
    scan_time: datetime
    risk_level: str
    risk_score: float
    entities_count: int
    entity_types: List[str]


class SystemScanner:
    """
    Full system scanner for building data inventory.
    
    Features:
    - Recursive directory scanning
    - Configurable exclusions (system folders, etc.)
    - Progress callbacks for UI updates
    - SQLite storage for scan results
    - Pause/Resume/Cancel support
    - Batch processing for efficiency
    """
    
    # Supported file extensions
    SUPPORTED_EXTENSIONS = {
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.csv',
        '.jpg', '.jpeg', '.png', '.tiff', '.bmp',
        '.odt', '.ods', '.rtf', '.html', '.xml', '.json',
        '.ppt', '.pptx', '.eml', '.msg'
    }
    
    # Default directories to exclude
    DEFAULT_EXCLUSIONS = {
        'Windows', 'Program Files', 'Program Files (x86)', 
        'ProgramData', '$Recycle.Bin', 'System Volume Information',
        'node_modules', '.git', '__pycache__', '.venv', 'venv',
        'AppData\\Local\\Temp', 'AppData\\Local\\Microsoft',
        '.cache', 'cache', 'Cache'
    }
    
    def __init__(self, db_path: str = None):
        """Initialize the scanner with database path"""
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), "..", "database", "scan_inventory.db"
            )
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_database()
        
        # Scan state
        self.progress = ScanProgress()
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        
        # Callbacks
        self.on_progress: Optional[Callable[[ScanProgress], None]] = None
        self.on_file_scanned: Optional[Callable[[ScannedFile], None]] = None
        self.on_complete: Optional[Callable[[ScanProgress], None]] = None
    
    def _init_database(self):
        """Create database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scanned_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER,
                file_hash TEXT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT,
                risk_score REAL,
                entities_count INTEGER,
                entity_types TEXT,
                last_modified TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                root_paths TEXT,
                total_files INTEGER,
                files_scanned INTEGER,
                files_with_pii INTEGER,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_risk_level 
            ON scanned_files(risk_level)
        ''')
        
        conn.commit()
        conn.close()
    
    def scan(self, 
             root_paths: List[str] = None,
             exclusions: List[str] = None,
             max_file_size_mb: int = 100) -> Dict[str, Any]:
        """
        Start a full system scan.
        
        Args:
            root_paths: Directories to scan. Defaults to user home and drives.
            exclusions: Additional paths to exclude
            max_file_size_mb: Maximum file size to scan in MB
            
        Returns:
            Scan initiation status
        """
        if self.progress.status == ScanStatus.SCANNING:
            return {"status": "already_scanning", "progress": self.progress.to_dict()}
        
        # Default paths
        if root_paths is None:
            root_paths = self._get_default_scan_paths()
        
        # Validate paths
        valid_paths = [p for p in root_paths if os.path.exists(p)]
        if not valid_paths:
            return {"status": "error", "message": "No valid paths to scan"}
        
        # Prepare exclusions
        all_exclusions = self.DEFAULT_EXCLUSIONS.copy()
        if exclusions:
            all_exclusions.update(exclusions)
        
        # Reset progress
        self.progress = ScanProgress(
            status=ScanStatus.SCANNING,
            start_time=time.time()
        )
        
        # Start scan thread
        self._stop_event.clear()
        self._pause_event.clear()
        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(valid_paths, all_exclusions, max_file_size_mb),
            daemon=True
        )
        self._scan_thread.start()
        
        return {
            "status": "started",
            "paths": valid_paths,
            "exclusions": list(all_exclusions)
        }
    
    def _get_default_scan_paths(self) -> List[str]:
        """Get default paths to scan"""
        paths = []
        
        # User directories
        home = Path.home()
        for subdir in ['Documents', 'Downloads', 'Desktop', 'Pictures']:
            path = home / subdir
            if path.exists():
                paths.append(str(path))
        
        return paths
    
    def _run_scan(self, root_paths: List[str], 
                  exclusions: set, max_file_size_mb: int):
        """Main scan execution (runs in background thread)"""
        try:
            # First pass: count files for progress tracking
            self.progress.total_files = self._count_files(root_paths, exclusions)
            
            # Second pass: scan files
            for root_path in root_paths:
                if self._stop_event.is_set():
                    break
                self._scan_directory(root_path, exclusions, max_file_size_mb)
            
            # Complete
            if self._stop_event.is_set():
                self.progress.status = ScanStatus.CANCELLED
            else:
                self.progress.status = ScanStatus.COMPLETED
            
            self.progress.elapsed_time = time.time() - self.progress.start_time
            
            # Save session
            self._save_scan_session(root_paths)
            
            # Callback
            if self.on_complete:
                self.on_complete(self.progress)
                
        except Exception as e:
            self.progress.status = ScanStatus.ERROR
            self.progress.errors.append(str(e))
    
    def _count_files(self, root_paths: List[str], exclusions: set) -> int:
        """Count files to scan for progress tracking"""
        count = 0
        for root_path in root_paths:
            for root, dirs, files in os.walk(root_path):
                # Filter excluded directories
                dirs[:] = [d for d in dirs if not self._should_exclude(os.path.join(root, d), exclusions)]
                
                for file in files:
                    if Path(file).suffix.lower() in self.SUPPORTED_EXTENSIONS:
                        count += 1
        return count
    
    def _scan_directory(self, root_path: str, 
                        exclusions: set, max_file_size_mb: int):
        """Recursively scan a directory"""
        max_size_bytes = max_file_size_mb * 1024 * 1024
        
        for root, dirs, files in os.walk(root_path):
            # Check stop signal
            if self._stop_event.is_set():
                return
            
            # Handle pause
            while self._pause_event.is_set() and not self._stop_event.is_set():
                time.sleep(0.5)
            
            # Filter excluded directories
            dirs[:] = [d for d in dirs if not self._should_exclude(os.path.join(root, d), exclusions)]
            
            self.progress.current_directory = root
            
            for file in files:
                if self._stop_event.is_set():
                    return
                
                file_path = os.path.join(root, file)
                
                # Check extension
                if Path(file).suffix.lower() not in self.SUPPORTED_EXTENSIONS:
                    continue
                
                # Check file size
                try:
                    if os.path.getsize(file_path) > max_size_bytes:
                        continue
                except OSError:
                    continue
                
                # Scan file
                self._scan_single_file(file_path)
    
    def _should_exclude(self, path: str, exclusions: set) -> bool:
        """Check if a path should be excluded"""
        path_lower = path.lower()
        for excl in exclusions:
            if excl.lower() in path_lower:
                return True
        return False
    
    def _scan_single_file(self, file_path: str):
        """Scan a single file for PII"""
        self.progress.current_file = file_path
        self.progress.files_scanned += 1
        self.progress.elapsed_time = time.time() - self.progress.start_time
        
        try:
            # Import modules
            from core.extractor import DocumentExtractor
            from core.detector import EntityDetector
            from features.risk_score import RiskScoreCalculator
            
            # Get file info
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            file_hash = self._compute_file_hash(file_path)
            
            # Check if already scanned (same hash)
            if self._is_already_scanned(file_path, file_hash):
                return
            
            # Extract text
            extractor = DocumentExtractor()
            extraction = extractor.extract(file_path)
            
            if not extraction or not extraction.get("text"):
                return
            
            # Detect entities
            detector = EntityDetector()
            entities = detector.detect(extraction["text"], extraction.get("coordinates", []))
            
            # Calculate risk
            risk_calc = RiskScoreCalculator()
            risk_result = risk_calc.calculate(entities, extraction["text"])
            
            # Create scanned file record
            entity_types = list(set(e.get("type", "") for e in entities))
            scanned_file = ScannedFile(
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_size,
                file_hash=file_hash,
                scan_time=datetime.now(timezone.utc),
                risk_level=risk_result.get("level", "MINIMAL"),
                risk_score=risk_result.get("score", 0),
                entities_count=len(entities),
                entity_types=entity_types
            )
            
            # Update progress
            if entities:
                self.progress.files_with_pii += 1
                
                if scanned_file.risk_level in ["CRITICAL", "HIGH"]:
                    self.progress.high_risk_files += 1
                elif scanned_file.risk_level == "MEDIUM":
                    self.progress.medium_risk_files += 1
                else:
                    self.progress.low_risk_files += 1
            
            # Save to database
            self._save_scanned_file(scanned_file)
            
            # Log to audit trail if PII detected
            if entities:
                try:
                    from core.audit import get_audit_logger
                    audit_logger = get_audit_logger()
                    doc_id = f"scan_{file_hash}"
                    audit_logger.log_processing(doc_id, entities, risk_result)
                except Exception:
                    pass  # Don't fail scan if audit fails
            
            # Callback
            if self.on_file_scanned:
                self.on_file_scanned(scanned_file)
            
            # Progress callback
            if self.on_progress and self.progress.files_scanned % 10 == 0:
                self.on_progress(self.progress)
                
        except Exception as e:
            self.progress.errors.append(f"{file_path}: {str(e)}")
    
    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of file (first 1MB only for speed)"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                # Read first 1MB
                data = f.read(1024 * 1024)
                sha256.update(data)
            return sha256.hexdigest()[:16]
        except:
            return ""
    
    def _is_already_scanned(self, file_path: str, file_hash: str) -> bool:
        """Check if file was already scanned with same hash"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT file_hash FROM scanned_files WHERE file_path = ?',
            (file_path,)
        )
        row = cursor.fetchone()
        conn.close()
        
        return row is not None and row[0] == file_hash
    
    def _save_scanned_file(self, scanned_file: ScannedFile):
        """Save scanned file to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO scanned_files 
            (file_path, file_name, file_size, file_hash, scan_time, 
             risk_level, risk_score, entities_count, entity_types)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scanned_file.file_path,
            scanned_file.file_name,
            scanned_file.file_size,
            scanned_file.file_hash,
            scanned_file.scan_time.isoformat(),
            scanned_file.risk_level,
            scanned_file.risk_score,
            scanned_file.entities_count,
            ','.join(scanned_file.entity_types)
        ))
        
        conn.commit()
        conn.close()
    
    def _save_scan_session(self, root_paths: List[str]):
        """Save scan session metadata"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_sessions 
            (start_time, end_time, root_paths, total_files, 
             files_scanned, files_with_pii, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.fromtimestamp(self.progress.start_time, tz=timezone.utc).isoformat(),
            datetime.now(timezone.utc).isoformat(),
            ','.join(root_paths),
            self.progress.total_files,
            self.progress.files_scanned,
            self.progress.files_with_pii,
            self.progress.status.value
        ))
        
        conn.commit()
        conn.close()
    
    def pause(self) -> Dict[str, Any]:
        """Pause the current scan"""
        if self.progress.status != ScanStatus.SCANNING:
            return {"status": "not_scanning"}
        
        self._pause_event.set()
        self.progress.status = ScanStatus.PAUSED
        return {"status": "paused", "progress": self.progress.to_dict()}
    
    def resume(self) -> Dict[str, Any]:
        """Resume a paused scan"""
        if self.progress.status != ScanStatus.PAUSED:
            return {"status": "not_paused"}
        
        self._pause_event.clear()
        self.progress.status = ScanStatus.SCANNING
        return {"status": "resumed", "progress": self.progress.to_dict()}
    
    def cancel(self) -> Dict[str, Any]:
        """Cancel the current scan"""
        if self.progress.status not in [ScanStatus.SCANNING, ScanStatus.PAUSED]:
            return {"status": "not_scanning"}
        
        self._stop_event.set()
        self._pause_event.clear()
        
        if self._scan_thread:
            self._scan_thread.join(timeout=5)
        
        return {"status": "cancelled", "progress": self.progress.to_dict()}
    
    def get_progress(self) -> Dict[str, Any]:
        """Get current scan progress"""
        return self.progress.to_dict()
    
    def get_risk_buckets(self) -> Dict[str, Any]:
        """Get files grouped by risk level"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get counts by risk level
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count, 
                   AVG(risk_score) as avg_score
            FROM scanned_files 
            WHERE entities_count > 0
            GROUP BY risk_level
        ''')
        
        buckets = {}
        for row in cursor.fetchall():
            buckets[row['risk_level']] = {
                "count": row['count'],
                "avg_score": round(row['avg_score'], 1) if row['avg_score'] else 0
            }
        
        # Get sample files for each bucket
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            cursor.execute('''
                SELECT file_path, file_name, risk_score, entities_count
                FROM scanned_files 
                WHERE risk_level = ?
                ORDER BY risk_score DESC
                LIMIT 10
            ''', (level,))
            
            if level not in buckets:
                buckets[level] = {"count": 0, "avg_score": 0}
            
            buckets[level]["files"] = [dict(row) for row in cursor.fetchall()]
        
        # Get total stats
        cursor.execute('SELECT COUNT(*) FROM scanned_files')
        total_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scanned_files WHERE entities_count > 0')
        files_with_pii = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_files_scanned": total_files,
            "files_with_pii": files_with_pii,
            "buckets": buckets
        }
    
    def get_files_by_risk(self, risk_level: str, limit: int = 100) -> List[Dict]:
        """Get files for a specific risk level"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scanned_files 
            WHERE risk_level = ?
            ORDER BY risk_score DESC
            LIMIT ?
        ''', (risk_level, limit))
        
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return files


# Global scanner instance
_system_scanner = None

def get_system_scanner() -> SystemScanner:
    """Get or create the global system scanner"""
    global _system_scanner
    if _system_scanner is None:
        _system_scanner = SystemScanner()
    return _system_scanner
