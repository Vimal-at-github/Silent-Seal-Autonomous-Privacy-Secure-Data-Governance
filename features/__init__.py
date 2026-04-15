# Features module init
from .risk_score import RiskScoreCalculator
from .synthetic_data import SyntheticDataGenerator
from .explainer import RedactionExplainer
from .adversarial import AdversarialTester
from .linkage import CrossDocumentLinkage
from .handwriting import HandwritingProcessor
from .privacy_analytics import PrivacyAnalytics
from .semantic_redaction import SemanticRedactor

# New features
from .notifications import NotificationManager, get_notification_manager
from .file_watcher import FileWatcher, get_file_watcher
from .system_scanner import SystemScanner, get_system_scanner
from .encryption import AESEncryption, RSAEncryption
from .vault import EncryptedVault, get_vault
from .file_inventory import FileInventory, get_file_inventory

# Feature Expansion 2.0
from .remediation import RemediationEngine, get_remediation_engine
from .rbac import RBACManager, get_rbac_manager
from .detection_modes import DetectionModeManager, get_detection_mode_manager
from .fingerprinting import DocumentFingerprinter, get_fingerprinter
from .reversible_redaction import ReversibleRedaction, get_reversible_redaction
from .collaboration import CollaborationManager, get_collaboration_manager
from .incident_playbook import IncidentPlaybook, get_incident_playbook
from .tamper_audit import TamperEvidentAudit, get_tamper_audit
from .compliance_export import ComplianceExporter, get_compliance_exporter
from .active_learning import ActiveLearning, get_active_learning
from .observability import ObservabilityManager, get_observability
from .privacy_graph import PrivacyGraph, get_privacy_graph

__all__ = [
    'RiskScoreCalculator',
    'SyntheticDataGenerator', 
    'RedactionExplainer',
    'AdversarialTester',
    'CrossDocumentLinkage',
    'HandwritingProcessor',
    'PrivacyAnalytics',
    'SemanticRedactor',
    # New features
    'NotificationManager',
    'get_notification_manager',
    'FileWatcher',
    'get_file_watcher',
    'SystemScanner',
    'get_system_scanner',
    'AESEncryption',
    'RSAEncryption',
    'EncryptedVault',
    'get_vault',
    'FileInventory',
    'get_file_inventory',
    # Feature Expansion 2.0
    'RemediationEngine', 'get_remediation_engine',
    'RBACManager', 'get_rbac_manager',
    'DetectionModeManager', 'get_detection_mode_manager',
    'DocumentFingerprinter', 'get_fingerprinter',
    'ReversibleRedaction', 'get_reversible_redaction',
    'CollaborationManager', 'get_collaboration_manager',
    'IncidentPlaybook', 'get_incident_playbook',
    'TamperEvidentAudit', 'get_tamper_audit',
    'ComplianceExporter', 'get_compliance_exporter',
    'ActiveLearning', 'get_active_learning',
    'ObservabilityManager', 'get_observability',
    'PrivacyGraph', 'get_privacy_graph'
]

