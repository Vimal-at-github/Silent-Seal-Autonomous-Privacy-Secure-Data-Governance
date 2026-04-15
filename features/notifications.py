"""
SilentSeal - Desktop Notifications
Cross-platform notification system for alerting users about sensitive files
"""

import threading
import queue
from typing import Dict, Any, Optional, Callable
from enum import Enum
import os


class NotificationPriority(Enum):
    """Notification priority levels based on risk"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationManager:
    """
    Cross-platform desktop notification manager.
    
    Features:
    - Windows: win10toast with action callbacks
    - Cross-platform fallback: plyer
    - Queue system for multiple notifications
    - Risk-level based priority and styling
    """
    
    def __init__(self):
        self.notification_queue = queue.Queue()
        self.is_running = False
        self._worker_thread = None
        self._toaster = None
        self._platform = self._detect_platform()
        self._init_notifier()
    
    def _detect_platform(self) -> str:
        """Detect the current operating system"""
        import platform
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        else:
            return "linux"
    
    def _init_notifier(self):
        """Initialize the appropriate notifier for the platform"""
        if self._platform == "windows":
            try:
                from win10toast import ToastNotifier
                self._toaster = ToastNotifier()
                print("Windows Toast notifications initialized")
            except ImportError:
                print("win10toast not available, falling back to plyer")
                self._toaster = None
        
        # Fallback or non-Windows
        if self._toaster is None:
            try:
                from plyer import notification as plyer_notification
                self._plyer = plyer_notification
                print("Plyer notifications initialized")
            except ImportError:
                self._plyer = None
                print("Warning: No notification library available")
    
    def notify(self, 
               title: str, 
               message: str, 
               priority: NotificationPriority = NotificationPriority.MEDIUM,
               icon_path: str = None,
               callback: Callable = None,
               duration: int = 10) -> bool:
        """
        Show a desktop notification
        
        Args:
            title: Notification title
            message: Notification body text
            priority: Priority level (affects styling)
            icon_path: Optional path to notification icon
            callback: Optional callback when notification is clicked
            duration: Duration in seconds
            
        Returns:
            True if notification was shown successfully
        """
        # Add priority prefix to title
        priority_prefix = self._get_priority_prefix(priority)
        full_title = f"{priority_prefix} {title}"
        
        try:
            if self._platform == "windows" and self._toaster:
                return self._show_windows_notification(
                    full_title, message, icon_path, duration, callback
                )
            elif hasattr(self, '_plyer') and self._plyer:
                return self._show_plyer_notification(
                    full_title, message, icon_path, duration
                )
            else:
                # Last resort: print to console
                print(f"[NOTIFICATION] {full_title}: {message}")
                return True
        except Exception as e:
            print(f"Notification error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _get_priority_prefix(self, priority: NotificationPriority) -> str:
        """Get visual prefix for priority level"""
        prefixes = {
            NotificationPriority.LOW: "ℹ️",
            NotificationPriority.MEDIUM: "⚠️",
            NotificationPriority.HIGH: "🔴",
            NotificationPriority.CRITICAL: "🚨"
        }
        return prefixes.get(priority, "")
    
    def _show_windows_notification(self, title: str, message: str,
                                     icon_path: str, duration: int,
                                     callback: Callable) -> bool:
        """Show Windows 10 toast notification"""
        try:
            # Threaded to prevent blocking
            self._toaster.show_toast(
                title=title,
                msg=message,
                icon_path=icon_path,
                duration=duration,
                threaded=True
            )
            return True
        except Exception as e:
            print(f"Windows notification error: {e}")
            return False
    
    def _show_plyer_notification(self, title: str, message: str,
                                   icon_path: str, duration: int) -> bool:
        """Show notification using plyer (cross-platform)"""
        try:
            self._plyer.notify(
                title=title,
                message=message,
                app_name="SilentSeal",
                app_icon=icon_path,
                timeout=duration
            )
            return True
        except Exception as e:
            print(f"Plyer notification error: {e}")
            return False
    
    def notify_sensitive_file(self, file_path: str, risk_level: str, 
                               entities_count: int, risk_score: float):
        """
        Show notification for a detected sensitive file
        
        Args:
            file_path: Path to the sensitive file
            risk_level: Risk level (HIGH, MEDIUM, LOW)
            entities_count: Number of sensitive entities found
            risk_score: Risk score (0-100)
        """
        filename = os.path.basename(file_path)
        
        # Determine priority from risk level
        priority_map = {
            "CRITICAL": NotificationPriority.CRITICAL,
            "HIGH": NotificationPriority.HIGH,
            "MEDIUM": NotificationPriority.MEDIUM,
            "LOW": NotificationPriority.LOW
        }
        priority = priority_map.get(risk_level, NotificationPriority.MEDIUM)
        
        # Build message
        title = f"Sensitive File Detected: {filename}"
        
        if risk_level in ["CRITICAL", "HIGH"]:
            message = (
                f"Risk Score: {risk_score:.0f}%\n"
                f"Found {entities_count} sensitive items.\n"
                f"⚠️ ENCRYPTION RECOMMENDED over redaction!"
            )
        else:
            message = (
                f"Risk Score: {risk_score:.0f}%\n"
                f"Found {entities_count} sensitive items.\n"
                f"Consider reviewing and redacting."
            )
        
        self.notify(title, message, priority)
    
    def notify_scan_complete(self, files_scanned: int, high_risk: int, 
                              medium_risk: int, low_risk: int):
        """Show notification when a scan completes"""
        title = "SilentSeal Scan Complete"
        message = (
            f"Scanned {files_scanned} files\n"
            f"🔴 High Risk: {high_risk}\n"
            f"🟡 Medium Risk: {medium_risk}\n"
            f"🟢 Low Risk: {low_risk}"
        )
        
        priority = NotificationPriority.CRITICAL if high_risk > 0 else NotificationPriority.MEDIUM
        self.notify(title, message, priority)
    
    def notify_encryption_complete(self, file_path: str, vault_path: str):
        """Show notification when file encryption completes"""
        filename = os.path.basename(file_path)
        title = "File Encrypted Successfully"
        message = f"'{filename}' has been encrypted and moved to the vault."
        self.notify(title, message, NotificationPriority.LOW)
    
    def start_queue_worker(self):
        """Start background worker for queued notifications"""
        if self.is_running:
            return
        
        self.is_running = True
        self._worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self._worker_thread.start()
    
    def stop_queue_worker(self):
        """Stop the background worker"""
        self.is_running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=2)
    
    def _process_queue(self):
        """Process notifications from the queue"""
        while self.is_running:
            try:
                notification = self.notification_queue.get(timeout=1)
                self.notify(**notification)
                self.notification_queue.task_done()
            except queue.Empty:
                continue
    
    def queue_notification(self, **kwargs):
        """Add notification to queue for async processing"""
        self.notification_queue.put(kwargs)


# Global instance
_notification_manager = None

def get_notification_manager() -> NotificationManager:
    """Get or create the global notification manager"""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager
