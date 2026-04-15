"""
SilentSeal - Legal-Ready Compliance Export
Generate GDPR, DPDP, CCPA, HIPAA reports and PIA templates.
"""
import os, json, hashlib, time
from typing import Dict, List
from datetime import datetime, timezone


COMPLIANCE_TEMPLATES = {
    'gdpr_article30': {
        'name': 'GDPR Article 30 — Records of Processing',
        'sections': ['Controller Details', 'Purposes of Processing', 'Categories of Data Subjects',
                     'Categories of Personal Data', 'Recipients', 'Transfers to Third Countries',
                     'Retention Periods', 'Technical & Organizational Measures']
    },
    'dpdp_compliance': {
        'name': 'DPDP Act Compliance Summary',
        'sections': ['Data Fiduciary Details', 'Purpose Limitation', 'Data Minimisation',
                     'Storage Limitation', 'Data Principal Rights', 'Consent Management',
                     'Significant Data Fiduciary Obligations', 'Cross-Border Transfer']
    },
    'ccpa_inventory': {
        'name': 'CCPA Data Inventory',
        'sections': ['Business Information', 'Categories of PI Collected', 'Sources of PI',
                     'Business Purposes', 'Third-Party Sharing', 'Consumer Rights Procedures']
    },
    'hipaa_phi_audit': {
        'name': 'HIPAA PHI Audit Report',
        'sections': ['Covered Entity Info', 'PHI Categories Found', 'Access Controls',
                     'Encryption Status', 'Minimum Necessary Standard', 'Breach Notification']
    }
}


class ComplianceExporter:
    """Generate legal-ready compliance reports and PIA templates."""

    def __init__(self, export_dir=None):
        if export_dir is None:
            export_dir = os.path.join(os.path.dirname(__file__), '..', 'exports', 'compliance')
        os.makedirs(export_dir, exist_ok=True)
        self.export_dir = export_dir

    def list_templates(self) -> List[Dict]:
        return [{'id': k, 'name': v['name'], 'sections': v['sections']}
                for k, v in COMPLIANCE_TEMPLATES.items()]

    def generate_report(self, template_id: str, scan_summary: Dict = None,
                        org_info: Dict = None) -> Dict:
        if template_id not in COMPLIANCE_TEMPLATES:
            return {'error': f'Unknown template: {template_id}'}
        tmpl = COMPLIANCE_TEMPLATES[template_id]
        scan = scan_summary or {}
        org = org_info or {'name': 'Organization', 'contact': 'DPO'}

        report = {
            'report_type': template_id,
            'report_name': tmpl['name'],
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'organization': org,
            'summary': {
                'total_files_scanned': scan.get('total_files', 0),
                'files_with_pii': scan.get('files_with_pii', 0),
                'entity_types_found': scan.get('entity_types', []),
                'risk_distribution': scan.get('risk_distribution', {}),
                'remediation_actions_taken': scan.get('remediation_count', 0),
            },
            'sections': {}
        }

        for section in tmpl['sections']:
            report['sections'][section] = {
                'status': 'review_required',
                'auto_populated': self._auto_populate(section, scan),
                'notes': ''
            }

        # Sign report
        content = json.dumps(report, sort_keys=True)
        report['integrity_hash'] = hashlib.sha256(content.encode()).hexdigest()

        path = os.path.join(self.export_dir, f'{template_id}_{int(time.time())}.json')
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)

        return {'report_path': path, 'report_name': tmpl['name'],
                'integrity_hash': report['integrity_hash']}

    def _auto_populate(self, section: str, scan: Dict) -> str:
        s = section.lower()
        if 'personal data' in s or 'pi collected' in s or 'phi' in s:
            types = scan.get('entity_types', [])
            return f"Detected entity types: {', '.join(types)}" if types else "No PII detected in scan"
        if 'encryption' in s:
            return "AES-256 encryption available via Secure Vault"
        if 'retention' in s or 'storage' in s:
            return "Review file retention policies — files in vault are encrypted at rest"
        if 'access' in s:
            return "RBAC system with role-based permissions and approval workflows"
        if 'breach' in s:
            return "Incident playbooks available for PII leak response"
        return "Manual review required"

    def generate_pia(self, project_name: str, data_types: List[str] = None,
                     processing_purposes: List[str] = None) -> Dict:
        pia = {
            'title': f'Privacy Impact Assessment — {project_name}',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'project': project_name,
            'sections': {
                'Data Inventory': {
                    'personal_data_types': data_types or [],
                    'status': 'review_required'
                },
                'Processing Purposes': {
                    'purposes': processing_purposes or [],
                    'legal_basis': 'To be determined',
                    'status': 'review_required'
                },
                'Risk Assessment': {
                    'inherent_risk': 'HIGH' if data_types and len(data_types) > 3 else 'MEDIUM',
                    'mitigations': ['Encryption at rest', 'RBAC access control', 'Audit logging',
                                    'Automated PII detection', 'Reversible redaction'],
                    'residual_risk': 'LOW'
                },
                'Data Subject Rights': {
                    'access': 'Supported via DSAR playbook',
                    'rectification': 'Supported via reversible redaction',
                    'erasure': 'Supported via redact & replace',
                    'portability': 'Supported via compliance export'
                },
                'Recommendations': [
                    'Enable strict detection mode for sensitive documents',
                    'Configure vault for all files with HIGH risk score',
                    'Set up incident playbooks for automated response',
                    'Enable tamper-evident audit logging'
                ]
            }
        }
        path = os.path.join(self.export_dir, f'pia_{project_name}_{int(time.time())}.json')
        with open(path, 'w') as f:
            json.dump(pia, f, indent=2)
        return {'pia_path': path, 'project': project_name}

    def get_data_subject_report(self, subject_identifier: str,
                                scan_results: List[Dict] = None) -> Dict:
        results = scan_results or []
        return {
            'subject': subject_identifier,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'occurrences': len(results),
            'files': [{'file': r.get('file', ''), 'entity_type': r.get('type', ''),
                        'context': r.get('context', '')} for r in results],
            'rights_available': ['Access', 'Rectification', 'Erasure', 'Portability', 'Objection']
        }


_exporter = None
def get_compliance_exporter():
    global _exporter
    if _exporter is None:
        _exporter = ComplianceExporter()
    return _exporter
