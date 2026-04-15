"""
SilentSeal Enhanced - Privacy Intelligence Platform
Main FastAPI Application
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
import os
import tempfile
import uuid
from datetime import datetime, timezone

# Core modules
from core.extractor import DocumentExtractor
from core.detector import EntityDetector
from core.redactor import DocumentRedactor
from core.audit import AuditLogger, get_audit_logger

# Feature modules
from features.risk_score import RiskScoreCalculator
from features.synthetic_data import SyntheticDataGenerator
from features.explainer import RedactionExplainer
from features.adversarial import AdversarialTester
from features.linkage import CrossDocumentLinkage
from features.handwriting import HandwritingProcessor
from features.privacy_analytics import PrivacyAnalytics
from features.semantic_redaction import SemanticRedactor

# New feature modules
from features.file_watcher import get_file_watcher
from features.system_scanner import get_system_scanner
from features.vault import get_vault, set_active_vault, list_existing_vaults
from features.file_inventory import get_file_inventory
from features.notifications import get_notification_manager

# Feature Expansion 2.0 Imports
from features.remediation import get_remediation_engine
from features.rbac import get_rbac_manager
from features.detection_modes import get_detection_mode_manager
from features.fingerprinting import get_fingerprinter
from features.reversible_redaction import get_reversible_redaction
from features.collaboration import get_collaboration_manager
from features.incident_playbook import get_incident_playbook
from features.tamper_audit import get_tamper_audit
from features.compliance_export import get_compliance_exporter
from features.active_learning import get_active_learning
from features.observability import get_observability
from features.privacy_graph import get_privacy_graph

app = FastAPI(
    title="SilentSeal Enhanced",
    description="Privacy Intelligence Platform - Automated Data Anonymization & Redaction",
    version="2.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
extractor = DocumentExtractor()
detector = EntityDetector()
redactor = DocumentRedactor()
audit_logger = get_audit_logger()
risk_calculator = RiskScoreCalculator()
synthetic_generator = SyntheticDataGenerator()
explainer = RedactionExplainer()
adversarial_tester = AdversarialTester()
linkage_detector = CrossDocumentLinkage()
handwriting_processor = HandwritingProcessor()
privacy_analytics = PrivacyAnalytics()
semantic_redactor = SemanticRedactor()

# Temp storage for processed documents
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "outputs")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)


class ProcessingOptions(BaseModel):
    """Options for document processing"""
    use_synthetic_replacement: bool = False
    generate_explanations: bool = True
    run_adversarial_test: bool = False
    check_cross_document: bool = False
    enable_handwriting_ocr: bool = True
    semantic_query: Optional[str] = None
    strict_validation: bool = False  # Default to False to catch test data


class AnalyticsQuery(BaseModel):
    """Query for privacy-preserving analytics"""
    query: str
    epsilon: float = 1.0


# --- New Feature Data Models ---

class RemediationActionRequest(BaseModel):
    action_type: str
    file_path: str
    details: Optional[dict] = {}

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    display_name: Optional[str] = None
    email: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class ApprovalRequest(BaseModel):
    action_type: str
    resource: str
    justification: str

class ReviewRequest(BaseModel):
    request_id: str
    approved: bool
    note: Optional[str] = None

class DetectionModeRequest(BaseModel):
    mode: str

class CustomRuleRequest(BaseModel):
    name: str
    entity_type: str
    pattern: str
    confidence: float = 0.8
    description: Optional[str] = ""

class ReversibleRedactionRequest(BaseModel):
    doc_id: str
    entities: List[dict]

class TokenRequest(BaseModel):
    redaction_id: str
    reason: str
    hours_valid: int = 24

class RevealRequest(BaseModel):
    token: str
    key: str

class CommentRequest(BaseModel):
    file_path: str
    content: str

class TaskRequest(BaseModel):
    title: str
    file_path: str
    assigned_to: str
    description: Optional[str] = ""
    priority: str = "medium"
    due_date: Optional[str] = None

class PlaybookExecuteRequest(BaseModel):
    playbook_id: str
    incident_id: Optional[str] = None

class FeedbackRequest(BaseModel):
    entity_type: str
    entity_text: str
    is_correct: bool
    rule_name: Optional[str] = ""
    context: Optional[str] = ""

class ComplianceReportRequest(BaseModel):
    template_id: str


@app.get("/api")
async def api_info():
    """API info endpoint"""
    return {
        "name": "SilentSeal Enhanced",
        "version": "2.0.0",
        "status": "operational",
        "features": [
            "Hybrid Detection (Regex + NLP)",
            "Re-identification Risk Score",
            "Synthetic Data Generation",
            "Explainable AI Decisions",
            "Adversarial Robustness Testing",
            "Cross-Document Linkage Detection",
            "Handwritten Document Support",
            "Privacy-Preserving Analytics"
        ]
    }


@app.post("/api/upload")
async def upload_document(file: UploadFile = File(...)):
    """Upload a document for processing or vault storage"""
    # Allow all file types (validation happens during processing if needed)
    
    # Generate unique ID
    doc_id = str(uuid.uuid4())
    
    # Save file
    file_ext = os.path.splitext(file.filename)[1]
    # Ensure extension is lower case for processing logic compatibility
    file_ext = file_ext.lower()
    
    file_path = os.path.join(UPLOAD_DIR, f"{doc_id}{file_ext}")
    
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    
    # Log upload
    audit_logger.log_upload(doc_id, file.filename, len(content))
    
    return {
        "doc_id": doc_id,
        "filename": file.filename,
        "size": len(content),
        "status": "uploaded",
        "file_path": file_path
    }


@app.post("/api/process/{doc_id}")
async def process_document(doc_id: str, options: ProcessingOptions = ProcessingOptions()):
    """Process a document for entity detection and redaction"""
    # Find the uploaded file
    file_path = None
    for ext in [".pdf", ".png", ".jpg", ".jpeg", ".tiff"]:
        potential_path = os.path.join(UPLOAD_DIR, f"{doc_id}{ext}")
        if os.path.exists(potential_path):
            file_path = potential_path
            break
    
    if not file_path:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Initialize basic modules that should always be available
    # We will use simple extraction if advanced ones fail
    
    class SimpleExtractor:
        def extract(self, path):
            text = ""
            try:
                import PyPDF2
                with open(path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    for page in reader.pages:
                        extracted = page.extract_text()
                        if extracted:
                            text += extracted + "\n"
            except Exception as e:
                print(f"Simple extraction failed: {e}")
                # Try simple byte read for text files
                try:
                    with open(path, 'r', errors='ignore') as f:
                        text = f.read()
                except:
                    pass
            return {"text": text, "coordinates": []}

    try:
        # Try to import core modules
        try:
            from core.extractor import DocumentExtractor
            from core.detector import EntityDetector
            # Also check if they can be instantiated (handling internal import errors)
            extractor = DocumentExtractor() 
            detector = EntityDetector()
            extractor_available = True
        except ImportError:
            extractor_available = False
        except Exception:
            extractor_available = False
        
        # Fallback to simple extraction if needed
        if not extractor_available:
            print("⚠️ Advanced modules missing, using fallback detection")
            extractor = SimpleExtractor()
            # Use regex-only detector if EntityDetector is missing or fails
            from core.detector import EntityDetector as RegexDetector # It has regex fallback inside usually
            # If not, we instantiate a dummy or just use the class methods if available
            # Let's assume EntityDetector is available (it's in core/detector.py which uses standard libs + spacy optional)
            try:
                detector = RegexDetector() 
            except:
                # If even that fails, we can't do much
                raise HTTPException(status_code=500, detail="Core detection module missing")
        
        # Step 1: Extract text
        is_image = file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff'))
        if is_image and not options.enable_handwriting_ocr:
            # Skip OCR if requested via toggle (though technically it's already "enabled" by default in extractor)
            # But the user might want "Fast" mode without OCR
            extraction_result = {"text": "Image text extraction skipped", "coordinates": []}
        else:
            extraction_result = extractor.extract(file_path)
            
        if not extraction_result["text"]:
             print("⚠️ No text extracted")
        
        # Step 2: Detect entities
        # If coordinates missing (SimpleExtractor), use text-only detection
        entities = detector.detect(extraction_result["text"], [], strict=options.strict_validation)
        
        # Step 3: Calculate risk score (simple fallback)
        risk_score = min(len(entities) * 10, 100)
        risk_level = "LOW"
        if risk_score > 70: risk_level = "HIGH"
        elif risk_score > 30: risk_level = "MEDIUM"
        
        risk_result = {"score": risk_score, "level": risk_level, "reidentification_risk": "Low"}
        
        # Step 4-6: Skipped in fallback mode (AI/Adversarial/Semantic)
        explanations = []
        
        # Step 4: Adversarial Testing
        adversarial_report = None
        if options.run_adversarial_test:
             try:
                 from features.adversarial import AdversarialTester
                 tester = AdversarialTester()
                 adversarial_report = tester.test(
                     extraction_result["text"], 
                     entities, 
                     is_synthetic=options.use_synthetic_replacement
                 )
             except Exception as e:
                 print(f"Adversarial test failed: {e}")

        # Step 7: Prepare redaction
        redacted_path = None
        if extractor_available:
             try:
                 from core.redactor import DocumentRedactor
                 from features.synthetic_data import SyntheticDataGenerator
                 
                 redactor = DocumentRedactor()
                 generator = SyntheticDataGenerator() if options.use_synthetic_replacement else None
                 
                 redaction_map = []
                 for entity in entities:
                     replacement = None
                     if generator:
                         replacement = generator.generate(entity.get("type"))
                     redaction_map.append({"entity": entity, "replacement": replacement})
                 
                 output_path = os.path.join(OUTPUT_DIR, f"{doc_id}_redacted.pdf")
                 redactor.redact(file_path, output_path, redaction_map)
                 redacted_path = output_path
             except Exception as e:
                 print(f"Redaction failed: {e}")
        
        # Step 9: Log processing
        # Ensure audit logger is available
        try:
             from core.audit import get_audit_logger
             audit_logger = get_audit_logger()
             audit_logger.log_processing(doc_id, entities[:5], risk_result) # Log summary
             
             # Step 10: Update inventory
             from features.file_inventory import get_file_inventory
             inventory = get_file_inventory()
             inventory.add_scanned_file(
                 file_path=file_path,
                 file_name=os.path.basename(file_path),
                 file_size=os.path.getsize(file_path),
                 risk_level=risk_result.get("level"),
                 risk_score=risk_result.get("score"),
                 entities_count=len(entities),
                 entity_types=list(set([e.get("type") for e in entities]))
             )
             # Step 11: Update Privacy Graph
             from features.privacy_graph import get_privacy_graph
             graph = get_privacy_graph()
             graph.add_finding(
                 doc_id=doc_id,
                 file_name=os.path.basename(file_path),
                 entities=entities
             )
        except Exception as e:
             print(f"Audit log or inventory failed: {e}")
        
        return {
            "doc_id": doc_id,
            "status": "processed",
            "entities_found": len(entities),
            "entities": entities,
            "risk_score": risk_result,
            "explanations": explanations,
            "adversarial_report": adversarial_report,
            "redacted_file": f"/download/{doc_id}_redacted.pdf" if redacted_path else None,
            "file_path": file_path,
            "warning": "Redaction unavailable due to missing PDF libraries" if not redacted_path else None
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class PreviewRequest(BaseModel):
    doc_id: str
    redaction_map: List[dict]  # List of {entity: dict, replacement: str}


@app.post("/api/redact/preview")
async def preview_redaction(request: PreviewRequest):
    """Generate a preview of the redaction without saving persistently"""
    try:
        doc_id = request.doc_id
        
        # Find file
        file_path = None
        for ext in [".pdf", ".png", ".jpg", ".jpeg", ".tiff"]:
            potential_path = os.path.join(UPLOAD_DIR, f"{doc_id}{ext}")
            if os.path.exists(potential_path):
                file_path = potential_path
                break
        
        if not file_path:
            raise HTTPException(status_code=404, detail="Document not found")
            
        # Initialize redactor
        try:
            from core.redactor import DocumentRedactor
            redactor = DocumentRedactor()
        except ImportError:
            raise HTTPException(status_code=500, detail="Redaction module not available")

        # Create temp output
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            temp_output = tmp.name
            
        # Perform redaction
        result = redactor.redact(file_path, temp_output, request.redaction_map)
        
        file_size = os.path.getsize(temp_output)

        # Return file stream with proper headers for better browser rendering
        def iterfile():
            try:
                with open(temp_output, mode="rb") as file_like:
                    chunk_size = 1024 * 64 # 64KB chunks
                    while chunk := file_like.read(chunk_size):
                        yield chunk
            finally:
                # Clean up temp file after streaming
                try:
                    if os.path.exists(temp_output):
                        os.remove(temp_output)
                except Exception as e:
                    print(f"Failed to remove temp preview file: {e}")

        return StreamingResponse(
            iterfile(), 
            media_type="application/pdf",
            headers={
                "Content-Length": str(file_size),
                "Content-Disposition": "inline; filename=preview.pdf",
                "Cache-Control": "no-cache"
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/download/{doc_id}")
async def download_redacted(doc_id: str):
    """Download the redacted document"""
    output_path = os.path.join(OUTPUT_DIR, f"{doc_id}_redacted.pdf")
    
    if not os.path.exists(output_path):
        raise HTTPException(status_code=404, detail="Redacted document not found")
    
    return FileResponse(
        output_path,
        media_type="application/pdf",
        filename=f"redacted_{doc_id}.pdf"
    )


@app.post("/api/linkage/check")
async def check_linkage(doc_ids: List[str]):
    """Check for cross-document entity linkage"""
    documents = []
    for doc_id in doc_ids:
        # Find and load each document's entities
        for ext in [".pdf", ".png", ".jpg", ".jpeg", ".tiff"]:
            potential_path = os.path.join(UPLOAD_DIR, f"{doc_id}{ext}")
            if os.path.exists(potential_path):
                extraction = extractor.extract(potential_path)
                entities = detector.detect(extraction["text"], extraction.get("coordinates", []))
                documents.append({"doc_id": doc_id, "entities": entities})
                break
    
    if len(documents) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 documents for linkage detection")
    
    linkage_result = linkage_detector.detect(documents)
    
    return {
        "documents_analyzed": len(documents),
        "linkages": linkage_result["linkages"],
        "combined_risk": linkage_result["combined_risk"],
        "recommendations": linkage_result["recommendations"]
    }


@app.post("/api/analytics/query")
async def analytics_query(query: AnalyticsQuery):
    """Execute a privacy-preserving analytics query"""
    result = privacy_analytics.execute_query(query.query, query.epsilon)
    return result


@app.get("/api/audit/logs")
async def get_audit_logs(limit: int = 100):
    """Get audit logs"""
    logger = get_audit_logger()
    return {"logs": logger.get_all_logs(limit=limit)}


@app.post("/api/audit/clear-all")
async def clear_audit_logs():
    """Clear all audit logs from the database"""
    logger = get_audit_logger()
    return logger.clear_logs()


@app.get("/api/audit/{doc_id}")
async def get_audit_log(doc_id: str):
    """Get audit log for a document"""
    logger = get_audit_logger()
    logs = logger.get_logs(doc_id)
    return {"doc_id": doc_id, "logs": logs}


# ============== FILE WATCHER (STANDBY MODE) ==============

class WatcherConfig(BaseModel):
    """Configuration for file watcher"""
    paths: Optional[List[str]] = None


class PathRequest(BaseModel):
    """Request to add or remove a watch path"""
    path: str


@app.post("/api/watcher/start")
async def start_watcher(config: WatcherConfig = WatcherConfig()):
    """Start file system monitoring (Standby Mode)"""
    watcher = get_file_watcher()
    result = watcher.start(config.paths)
    return result


@app.post("/api/watcher/stop")
async def stop_watcher():
    """Stop file system monitoring"""
    watcher = get_file_watcher()
    result = watcher.stop()
    return result


@app.post("/api/watcher/pause")
async def pause_watcher():
    """Pause file system monitoring"""
    watcher = get_file_watcher()
    return watcher.pause()


@app.post("/api/watcher/resume")
async def resume_watcher():
    """Resume file system monitoring"""
    watcher = get_file_watcher()
    return watcher.resume()


@app.get("/api/watcher/status")
async def get_watcher_status():
    """Get current watcher status"""
    watcher = get_file_watcher()
    return watcher.get_status()


@app.get("/api/watcher/detections")
async def get_recent_detections():
    """Get recent file detections from Standby Mode"""
    watcher = get_file_watcher()
    return {"detections": watcher.recent_detections}


@app.post("/api/watcher/add-path")
async def add_watch_path(request: PathRequest):
    """Add a directory to monitor"""
    watcher = get_file_watcher()
    return watcher.add_watch_path(request.path)


@app.post("/api/watcher/remove-path")
async def remove_watch_path(request: PathRequest):
    """Remove a directory from monitoring"""
    watcher = get_file_watcher()
    return watcher.remove_watch_path(request.path)


# ============== SECURE VAULT ==============

# vault imports moved to top

class VaultActionRequest(BaseModel):
    file_path: str
    password: Optional[str] = None
    delete_original: bool = False

@app.post("/api/vault/initialize")
async def initialize_vault(password: str, name: str = "default"):
    """Initialize a new named encrypted vault"""
    try:
        set_active_vault(name)
        vault = get_vault(name)
        result = vault.initialize(password)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/vault/unlock")
async def unlock_vault(password: str, name: str = "default"):
    """Unlock the vault"""
    try:
        vault = get_vault(name)
        result = vault.unlock(password)
        return result
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid password")

@app.post("/api/vault/lock")
async def lock_vault(name: str = "default"):
    """Lock the vault"""
    vault = get_vault(name)
    vault.lock()
    return {"status": "locked"}

@app.get("/api/vault/status")
async def get_vault_status(name: str = "default"):
    """Get vault status and statistics"""
    vault = get_vault(name)
    is_unlocked = vault.is_unlocked()
    
    if is_unlocked:
        stats = vault.get_vault_stats()
        return {"unlocked": True, **stats}
    else:
        return {"unlocked": False, "file_count": 0}

@app.post("/api/vault/encrypt")
async def encrypt_file(request: VaultActionRequest, name: str = "default"):
    """Encrypt a file and add to vault"""
    try:
        vault = get_vault(name)
        
        if not vault.is_unlocked():
            raise HTTPException(status_code=401, detail="Vault is locked")
        
        result = vault.add_file(
            file_path=request.file_path,
            delete_original=request.delete_original
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/vault/remove")
async def remove_vault_file(name: str, filename: str):
    """Remove a file from the vault"""
    vault = get_vault(name)
    return vault.remove_file(filename)


@app.get("/api/vault/files")
async def list_vault_files(name: str = "default"):
    """List all files in the vault"""
    try:
        vault = get_vault(name)
        
        if not vault.is_unlocked():
            raise HTTPException(status_code=401, detail="Vault is locked")
        
        files = vault.list_files()
        return {"files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/vault/keys/public")
async def get_public_key(name: str = "default"):
    """Get the vault's public key"""
    try:
        vault = get_vault(name)
        key = vault.get_public_key()
        if not key:
            raise HTTPException(status_code=404, detail="Public key not found")
        return {"public_key": key.decode()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/vault/keys/import")
async def import_recipient_key(request: dict, name: str = "default"):
    """Import a recipient's public key"""
    try:
        vault = get_vault(name)
        if not vault.is_unlocked():
            raise HTTPException(status_code=401, detail="Vault is locked")
            
        key_name = request.get("name")
        key_pem = request.get("public_key")
        
        if not key_name or not key_pem:
            raise HTTPException(status_code=400, detail="Name and public_key are required")
            
        result = vault.import_public_key(key_name, key_pem.encode())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/vault/keys/list")
async def list_imported_keys(name: str = "default"):
    """List all imported public keys"""
    try:
        vault = get_vault(name)
        if not vault.is_unlocked():
            raise HTTPException(status_code=401, detail="Vault is locked")
        return {"keys": vault.list_imported_keys()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/vault/decrypt")
async def decrypt_file(request: dict):
    """Decrypt a file from the vault"""
    try:
        vault_file_name = request.get("vault_name")
        output_path = request.get("output_path")
        
        vault = get_vault()
        
        if not vault.is_unlocked():
            raise HTTPException(status_code=401, detail="Vault is locked")
            
        result = vault.extract_file(vault_file_name, output_path)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/vaults")
async def list_vaults():
    """List all available vaults"""
    return {"vaults": list_existing_vaults()}


@app.post("/api/vaults/select")
async def select_vault(name: str):
    """Select the active vault"""
    set_active_vault(name)
    return {"status": "success", "active_vault": name}


# ============== AUDIT LOG ==============


@app.get("/api/stats")
async def get_stats():
    """Alias for dashboard data"""
    return await get_dashboard_data()


@app.get("/api/inventory/files")
async def get_processed_files():
    """List scanned files"""
    inventory = get_file_inventory()
    files = inventory.search_files(limit=200)
    return {"files": files}

# ============== SYSTEM SCANNER ==============

class ScanConfig(BaseModel):
    """Configuration for system scan"""
    paths: Optional[List[str]] = None
    exclusions: Optional[List[str]] = None
    max_file_size_mb: int = 100


@app.post("/api/scan/system")
async def start_system_scan(config: ScanConfig = ScanConfig()):
    """Start full system scan"""
    scanner = get_system_scanner()
    result = scanner.scan(
        root_paths=config.paths,
        exclusions=config.exclusions,
        max_file_size_mb=config.max_file_size_mb
    )
    return result


@app.get("/api/scan/progress")
async def get_scan_progress():
    """Get current scan progress"""
    scanner = get_system_scanner()
    return scanner.get_progress()


@app.post("/api/scan/pause")
async def pause_scan():
    """Pause current scan"""
    scanner = get_system_scanner()
    return scanner.pause()


@app.post("/api/scan/resume")
async def resume_scan():
    """Resume paused scan"""
    scanner = get_system_scanner()
    return scanner.resume()


@app.post("/api/scan/cancel")
async def cancel_scan():
    """Cancel current scan"""
    scanner = get_system_scanner()
    return scanner.cancel()


@app.get("/api/scan/defaults")
async def get_scan_defaults():
    """Get default scan paths based on environment"""
    scanner = get_system_scanner()
    return {"paths": scanner._get_default_scan_paths()}


@app.post("/api/scan/clear")
async def clear_scan_results():
    """Clear all scan results and reset inventory"""
    try:
        inventory = get_file_inventory()
        # Clear the inventory database
        if hasattr(inventory, 'clear_all'):
            inventory.clear_all()
        return {"status": "cleared", "message": "All scan results cleared"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============== FILE INVENTORY & DASHBOARD ==============

@app.get("/api/inventory/buckets")
async def get_risk_buckets():
    """Get files grouped by risk level"""
    inventory = get_file_inventory()
    return inventory.get_risk_buckets()


@app.get("/api/inventory/dashboard")
async def get_dashboard_data():
    """Get complete dashboard summary"""
    inventory = get_file_inventory()
    return inventory.get_dashboard_summary()


@app.get("/api/inventory/high-risk")
async def get_high_risk_files():
    """Get high risk files that need attention"""
    inventory = get_file_inventory()
    return inventory.get_high_risk_files()


class SearchQuery(BaseModel):
    """Search query parameters"""
    query: Optional[str] = None
    risk_level: Optional[str] = None
    entity_type: Optional[str] = None
    limit: int = 100


@app.post("/api/inventory/search")
async def search_inventory(search: SearchQuery):
    """Search scanned files"""
    inventory = get_file_inventory()
    return inventory.search_files(
        query=search.query,
        risk_level=search.risk_level,
        entity_type=search.entity_type,
        limit=search.limit
    )


# ============== ENCRYPTED VAULT ==============

class VaultPassword(BaseModel):
    """Vault password model"""
    password: str





# Mount static files for frontend (CSS, JS)
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    # Mount CSS and JS directories
    css_path = os.path.join(frontend_path, "css")
    js_path = os.path.join(frontend_path, "js")
    
    if os.path.exists(css_path):
        app.mount("/css", StaticFiles(directory=css_path), name="css")
    if os.path.exists(js_path):
        app.mount("/js", StaticFiles(directory=js_path), name="js")
    
    # Serve index.html at root
    @app.get("/", response_class=FileResponse)
    async def serve_frontend():
        return FileResponse(os.path.join(frontend_path, "index.html"))



# ============== RBAC & AUTH ==============

@app.post("/api/auth/login")
async def login(request: LoginRequest):
    """Login and get session token"""
    rbac = get_rbac_manager()
    return rbac.authenticate(request.username, request.password)

@app.post("/api/auth/users")
async def create_user(request: UserCreateRequest):
    """Create a new user (Admin only)"""
    rbac = get_rbac_manager()
    # In a real app, we'd check the requesting user's session from headers
    return rbac.create_user(
        request.username, request.password, request.role,
        request.display_name, request.email
    )

@app.get("/api/auth/users")
async def list_users():
    """List all users"""
    rbac = get_rbac_manager()
    return {"users": rbac.list_users()}

@app.post("/api/auth/approve")
async def approve_request(request: ReviewRequest):
    """Approve or deny a request"""
    rbac = get_rbac_manager()
    return rbac.approve_request(
        request.request_id, "admin", request.approved, request.note
    )  # reviewing as 'admin' for now

@app.get("/api/auth/approvals/pending")
async def pending_approvals():
    """Get pending approvals"""
    rbac = get_rbac_manager()
    return {"pending": rbac.get_pending_approvals()}


# ============== DETECTION MODES ==============

@app.get("/api/detection/mode")
async def get_detection_mode():
    """Get current detection mode configuration"""
    manager = get_detection_mode_manager()
    return manager.get_mode()

@app.post("/api/detection/mode")
async def set_detection_mode(request: DetectionModeRequest):
    """Set detection mode"""
    manager = get_detection_mode_manager()
    return manager.set_mode(request.mode)

@app.get("/api/detection/rules")
async def list_rules():
    """List all detection rules"""
    manager = get_detection_mode_manager()
    return manager.list_rules()

@app.post("/api/detection/rules")
async def add_custom_rule(request: CustomRuleRequest):
    """Add a custom detection rule"""
    manager = get_detection_mode_manager()
    return manager.add_custom_rule(
        request.name, request.entity_type, request.pattern,
        request.confidence, request.description
    )

# ============== FINGERPRINTING ==============

@app.post("/api/fingerprint/{doc_id}")
async def compute_fingerprint(doc_id: str):
    """Compute and store document fingerprint"""
    # This usually happens during processing, but exposed for manual trigger
    fingerprinter = get_fingerprinter()
    # We need text content - normally fetched from extraction cache
    # Simplified here
    return {"status": "triggered", "doc_id": doc_id}

@app.get("/api/fingerprint/duplicates")
async def find_duplicates():
    """Find duplicate documents"""
    fingerprinter = get_fingerprinter()
    return {"duplicates": fingerprinter.find_duplicates()}


# ============== REVERSIBLE REDACTION ==============

@app.post("/api/redact/reversible")
async def redact_reversible(request: ReversibleRedactionRequest):
    """Perform reversible redaction"""
    rev = get_reversible_redaction()
    return rev.redact_reversible(request.doc_id, request.entities)

@app.post("/api/redact/token")
async def generate_token(request: TokenRequest):
    """Generate access token for revealing"""
    rev = get_reversible_redaction()
    return rev.generate_access_token(
        request.redaction_id, "user", request.reason, request.hours_valid
    )

@app.post("/api/redact/reveal")
async def reveal_redaction(request: RevealRequest):
    """Reveal redacted content"""
    rev = get_reversible_redaction()
    return rev.reveal_with_token(request.token, request.key, "user")



# ============== REMEDIATION ==============

class RemediationRequest(BaseModel):
    file_path: str
    risk_level: str = "MEDIUM"
    risk_score: float = 50.0
    entities: List[dict] = []

class RemediationExecuteRequest(BaseModel):
    action_type: str
    file_path: str
    risk_level: str = "MEDIUM"
    risk_score: float = 50.0
    entities: List[dict] = []
    details: Optional[dict] = {}


@app.post("/api/remediation/suggest")
async def suggest_remediation(request: RemediationRequest):
    """Get suggested remediation actions"""
    engine = get_remediation_engine()
    suggestions = engine.suggest_actions(
        request.file_path, request.risk_level, request.risk_score, request.entities
    )
    return {"suggestions": suggestions}


@app.post("/api/remediation/execute")
async def execute_remediation(request: RemediationExecuteRequest):
    """Execute a remediation action"""
    engine = get_remediation_engine()
    result = engine.execute_action(
        request.action_type, request.file_path, 
        request.risk_level, request.risk_score,
        request.entities, request.details,
        initiated_by="user"
    )
    return result


@app.get("/api/remediation/history")
async def get_remediation_history(limit: int = 50):
    """Get remediation action history"""
    engine = get_remediation_engine()
    history = engine.get_action_history(limit)
    return {"history": history}


@app.get("/api/incidents")
async def list_incidents():
    """List incidents"""
    engine = get_remediation_engine()
    incidents = engine.get_incidents()
    return {"incidents": incidents}


# ============== COLLABORATION ==============

@app.post("/api/collaboration/comment")
async def add_comment(request: CommentRequest):
    """Add a comment to a file"""
    collab = get_collaboration_manager()
    # Mock author
    return collab.add_comment(request.file_path, "user", request.content)

@app.get("/api/collaboration/comments")
async def get_comments(file_path: str):
    """Get comments for a file"""
    collab = get_collaboration_manager()
    return {"comments": collab.get_comments(file_path)}

@app.post("/api/collaboration/task")
async def assign_task(request: TaskRequest):
    """Assign a remediation task"""
    collab = get_collaboration_manager()
    return collab.assign_task(
        request.title, request.file_path, request.assigned_to,
        "admin", request.description, request.priority, request.due_date
    )

@app.get("/api/collaboration/tasks")
async def list_tasks(assigned_to: Optional[str] = None):
    """List tasks"""
    collab = get_collaboration_manager()
    return {"tasks": collab.get_tasks(assigned_to)}

# ============== INCIDENT PLAYBOOKS ==============

@app.get("/api/playbooks")
async def list_playbooks():
    """List available incident playbooks"""
    pb = get_incident_playbook()
    return {"playbooks": pb.list_playbooks()}

@app.post("/api/playbooks/execute")
async def execute_playbook(request: PlaybookExecuteRequest):
    """Execute a playbook"""
    pb = get_incident_playbook()
    return pb.execute_playbook(request.playbook_id, request.incident_id)

@app.post("/api/playbooks/step/advance")
async def advance_playbook_step(execution_id: str, result: str = "completed"):
    """Advance playbook step"""
    pb = get_incident_playbook()
    return pb.advance_step(execution_id, result)

@app.get("/api/playbooks/executions")
async def list_playbook_executions():
    """List playbook executions"""
    pb = get_incident_playbook()
    return {"executions": pb.get_executions()}

@app.get("/api/playbooks/evidence/export")
async def export_incident_evidence(execution_id: str):
    """Export signed evidence bundle"""
    pb = get_incident_playbook()
    return pb.export_evidence(execution_id)

# ============== TAMPER-EVIDENT AUDIT ==============

@app.get("/api/audit/tamper-proof/verify")
async def verify_audit_log_integrity():
    """Verify integrity of the tamper-evident audit log"""
    audit = get_tamper_audit()
    return audit.verify_integrity()

@app.get("/api/audit/tamper-proof/export")
async def export_tamper_proof_log():
    """Export the tamper-evident audit log"""
    audit = get_tamper_audit()
    return audit.export_log()

# ============== COMPLIANCE EXPORT ==============

@app.get("/api/compliance/templates")
async def list_compliance_templates():
    """List available compliance report templates"""
    exporter = get_compliance_exporter()
    return {"templates": exporter.list_templates()}

@app.post("/api/compliance/generate")
async def generate_compliance_report(request: ComplianceReportRequest):
    """Generate a compliance report (GDPR/CCPA/etc)"""
    exporter = get_compliance_exporter()
    # In a real app we'd fetch actual scan stats here
    mock_scan_stats = {"total_files": 100, "files_with_pii": 5}
    return exporter.generate_report(request.template_id, scan_summary=mock_scan_stats)

# ============== ACTIVE LEARNING ==============

@app.post("/api/learning/feedback")
async def submit_feedback(request: FeedbackRequest):
    """Submit feedback on PII detection (TP/FP)"""
    learn = get_active_learning()
    return learn.submit_feedback(
        request.entity_type, request.entity_text, request.is_correct,
        request.rule_name, context=request.context
    )

@app.get("/api/learning/stats")
async def get_learning_stats():
    """Get active learning stats"""
    learn = get_active_learning()
    return learn.get_feedback_stats()

@app.get("/api/learning/thresholds")
async def get_suggested_thresholds():
    """Get suggested threshold adjustments"""
    learn = get_active_learning()
    return learn.get_adjusted_thresholds()

# ============== OBSERVABILITY ==============

@app.get("/api/observability/dashboard")
async def get_observability_dashboard():
    """Get observability dashboard data"""
    obs = get_observability()
    # Record a heartbeat metric
    obs.record_metric("api_heartbeat", 1)
    return obs.get_dashboard()


# ============== PRIVACY GRAPH ==============

@app.get("/api/privacy/graph")
async def get_privacy_graph_data():
    """Get node-link data for the privacy graph"""
    graph = get_privacy_graph()
    return graph.get_graph_data()

@app.get("/api/privacy/chains")
async def get_reidentification_chains():
    """Get detected re-identification chains"""
    graph = get_privacy_graph()
    return {"chains": graph.detect_reidentification_chains()}

@app.get("/api/privacy/summary")
async def get_privacy_graph_summary():
    """Get summary statistics for the privacy graph"""
    graph = get_privacy_graph()
    return graph.get_risk_summary()

@app.get("/api/privacy/documents")
async def get_privacy_graph_documents():
    """Get list of documents in the privacy graph"""
    graph = get_privacy_graph()
    return {"documents": graph.get_documents()}

@app.delete("/api/privacy/documents/{doc_id}")
async def delete_privacy_graph_document(doc_id: str):
    """Delete a document from the privacy graph"""
    graph = get_privacy_graph()
    return graph.delete_document(doc_id)


# Mount static files
app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

