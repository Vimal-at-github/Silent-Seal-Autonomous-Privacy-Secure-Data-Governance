"""
SilentSeal - Explainable AI Redaction Decisions
Novel feature: Generates human-readable explanations for each redaction decision
"""

from typing import Dict, List, Any, Optional
import re


class RedactionExplainer:
    """
    Generates natural language explanations for redaction decisions
    
    This is a NOVEL FEATURE that provides transparency and auditability
    for AI-driven redaction decisions, supporting:
    - Legal compliance (ability to justify decisions)
    - Human oversight (understanding AI behavior)
    - Error correction (identifying false positives)
    """
    
    # Legal references for different entity types
    LEGAL_REFERENCES = {
        "AADHAAR": {
            "regulation": "Aadhaar Act 2016, Section 29",
            "category": "Biometric and Demographic Information",
            "sensitivity": "HIGH",
            "reason": "Unique identification number linked to biometric data"
        },
        "PAN": {
            "regulation": "Income Tax Act 1961, Information Technology Act 2000",
            "category": "Financial Identifier",
            "sensitivity": "HIGH",
            "reason": "Tax identification enabling financial tracking"
        },
        "EMAIL": {
            "regulation": "IT Act 2000, DPDP Act 2023 Section 2(t)",
            "category": "Personal Contact Information",
            "sensitivity": "MEDIUM",
            "reason": "Personal identifier enabling direct contact"
        },
        "PHONE": {
            "regulation": "DPDP Act 2023, TRAI Regulations",
            "category": "Personal Contact Information",
            "sensitivity": "MEDIUM",
            "reason": "Personal identifier linked to mobile KYC"
        },
        "PERSON_NAME": {
            "regulation": "DPDP Act 2023 Section 2(t), HIPAA (if medical)",
            "category": "Personal Identifier",
            "sensitivity": "MEDIUM-HIGH",
            "reason": "Direct identifier of individual"
        },
        "DATE_OF_BIRTH": {
            "regulation": "DPDP Act 2023, HIPAA Section 164.514(b)(2)",
            "category": "Quasi-Identifier",
            "sensitivity": "MEDIUM",
            "reason": "Combined with other data enables re-identification"
        },
        "LOCATION": {
            "regulation": "DPDP Act 2023, GDPR Article 4(1)",
            "category": "Geographic Identifier",
            "sensitivity": "LOW-MEDIUM",
            "reason": "Location data can narrow anonymity set"
        },
        "ORGANIZATION": {
            "regulation": "Context-dependent",
            "category": "Affiliation Information",
            "sensitivity": "LOW",
            "reason": "May reveal employment or association"
        },
        "CREDIT_CARD": {
            "regulation": "PCI-DSS, RBI Circular",
            "category": "Financial Payment Information",
            "sensitivity": "CRITICAL",
            "reason": "Payment card data requiring strict protection"
        },
        "BANK_ACCOUNT": {
            "regulation": "Banking Regulation Act, IT Act 2000",
            "category": "Financial Account Information",
            "sensitivity": "HIGH",
            "reason": "Bank account enabling financial transactions"
        },
        "PASSPORT": {
            "regulation": "Passport Act 1967",
            "category": "Government ID",
            "sensitivity": "HIGH",
            "reason": "Unique government-issued travel document"
        },
        "DRIVING_LICENSE": {
            "regulation": "Motor Vehicles Act 1988",
            "category": "Government ID",
            "sensitivity": "HIGH",
            "reason": "Unique government-issued identification"
        },
        "IP_ADDRESS": {
            "regulation": "IT Act 2000, GDPR Article 4(1)",
            "category": "Technical Identifier",
            "sensitivity": "MEDIUM",
            "reason": "Can identify location and internet activity"
        }
    }
    
    # Context patterns for enhanced explanations
    CONTEXT_PATTERNS = {
        "medical": {
            "keywords": ["patient", "diagnosis", "treatment", "hospital", "doctor", "prescription", "medical", "health"],
            "regulation_boost": "HIPAA PHI category",
            "sensitivity_boost": 2
        },
        "financial": {
            "keywords": ["salary", "income", "bank", "account", "tax", "payment", "loan", "credit"],
            "regulation_boost": "Financial services regulation",
            "sensitivity_boost": 1
        },
        "employment": {
            "keywords": ["employee", "hr", "performance", "appraisal", "employment", "job"],
            "regulation_boost": "Employment records protection",
            "sensitivity_boost": 1
        },
        "legal": {
            "keywords": ["court", "case", "attorney", "lawyer", "judgment", "legal"],
            "regulation_boost": "Legal privilege considerations",
            "sensitivity_boost": 1
        }
    }
    
    def __init__(self, use_llm: bool = False):
        """
        Initialize explainer
        
        Args:
            use_llm: Whether to use LLM for enhanced explanations (requires Ollama)
        """
        self.use_llm = use_llm
        self.llm = None
        
        if use_llm:
            self._init_llm()
    
    def _init_llm(self):
        """Initialize local LLM for enhanced explanations"""
        try:
            # Try to connect to Ollama
            import requests
            response = requests.get("http://localhost:11434/api/tags", timeout=2)
            if response.status_code == 200:
                self.llm = "ollama"
        except:
            self.llm = None
            print("Warning: LLM not available, using rule-based explanations")
    
    def explain(self, entity: Dict, full_text: str, surrounding_context: str = None) -> Dict[str, Any]:
        """
        Generate explanation for a single entity redaction
        
        Args:
            entity: Detected entity with type, text, confidence
            full_text: Full document text
            surrounding_context: Text around the entity
            
        Returns:
            Explanation dictionary
        """
        entity_type = entity.get("type", "UNKNOWN")
        entity_text = entity.get("text", "")
        confidence = entity.get("confidence", 0)
        detection_method = entity.get("method", "unknown")
        
        # Get legal reference
        legal_info = self.LEGAL_REFERENCES.get(entity_type, {
            "regulation": "General data protection principles",
            "category": "Personal Information",
            "sensitivity": "MEDIUM",
            "reason": "May contain identifiable information"
        })
        
        # Analyze context
        context_analysis = self._analyze_context(full_text, entity_type)
        
        # Generate explanation components
        decision_reason = self._generate_decision_reason(entity, legal_info, context_analysis)
        risk_assessment = self._assess_risk(entity, context_analysis)
        recommendation = self._generate_recommendation(entity, legal_info, context_analysis)
        
        # Build comprehensive explanation
        explanation = {
            "entity": {
                "type": entity_type,
                "preview": entity_text[:3] + "***" if len(entity_text) > 3 else "***",
                "confidence": confidence,
                "detection_method": detection_method
            },
            "decision": "REDACT",
            "decision_reason": decision_reason,
            "legal_basis": {
                "regulation": legal_info["regulation"],
                "category": legal_info["category"],
                "base_sensitivity": legal_info["sensitivity"],
                "context_sensitivity": context_analysis.get("adjusted_sensitivity", legal_info["sensitivity"])
            },
            "risk_assessment": risk_assessment,
            "context_factors": context_analysis.get("detected_contexts", []),
            "recommendation": recommendation,
            "human_readable": self._format_human_readable(
                entity_type, decision_reason, legal_info, context_analysis, confidence
            )
        }
        
        # Enhance with LLM if available
        if self.llm and surrounding_context:
            explanation["llm_enhanced"] = self._llm_enhance(entity, surrounding_context)
        
        return explanation
    
    def explain_all(self, entities: List[Dict], full_text: str) -> List[Dict]:
        """Generate explanations for all entities"""
        explanations = []
        
        for entity in entities:
            # Extract surrounding context (100 chars before and after)
            start = entity.get("start", 0)
            end = entity.get("end", len(entity.get("text", "")))
            
            context_start = max(0, start - 100)
            context_end = min(len(full_text), end + 100)
            surrounding_context = full_text[context_start:context_end]
            
            explanation = self.explain(entity, full_text, surrounding_context)
            explanations.append(explanation)
        
        return explanations
    
    def _analyze_context(self, full_text: str, entity_type: str) -> Dict:
        """Analyze document context for the entity"""
        lower_text = full_text.lower()
        
        detected_contexts = []
        sensitivity_boost = 0
        regulation_additions = []
        
        for context_name, context_info in self.CONTEXT_PATTERNS.items():
            if any(keyword in lower_text for keyword in context_info["keywords"]):
                detected_contexts.append(context_name)
                sensitivity_boost += context_info["sensitivity_boost"]
                regulation_additions.append(context_info["regulation_boost"])
        
        # Adjust sensitivity
        base_sensitivity = self.LEGAL_REFERENCES.get(entity_type, {}).get("sensitivity", "MEDIUM")
        sensitivity_levels = ["LOW", "LOW-MEDIUM", "MEDIUM", "MEDIUM-HIGH", "HIGH", "CRITICAL"]
        
        try:
            base_index = sensitivity_levels.index(base_sensitivity)
            adjusted_index = min(base_index + sensitivity_boost, len(sensitivity_levels) - 1)
            adjusted_sensitivity = sensitivity_levels[adjusted_index]
        except ValueError:
            adjusted_sensitivity = base_sensitivity
        
        return {
            "detected_contexts": detected_contexts,
            "sensitivity_boost": sensitivity_boost,
            "adjusted_sensitivity": adjusted_sensitivity,
            "regulation_additions": regulation_additions
        }
    
    def _generate_decision_reason(self, entity: Dict, legal_info: Dict, context: Dict) -> str:
        """Generate the decision reason"""
        entity_type = entity.get("type", "UNKNOWN")
        confidence = entity.get("confidence", 0)
        method = entity.get("method", "detection")
        
        reasons = []
        
        # Detection confidence
        if confidence >= 0.9:
            reasons.append(f"High-confidence {method} detection ({confidence*100:.0f}%)")
        else:
            reasons.append(f"Detected via {method} with {confidence*100:.0f}% confidence")
        
        # Legal categorization
        reasons.append(f"Classified as {legal_info['category']}")
        
        # Context factors
        if context.get("detected_contexts"):
            contexts = ", ".join(context["detected_contexts"])
            reasons.append(f"Found in {contexts} context, increasing sensitivity")
        
        # Core reason
        reasons.append(legal_info["reason"])
        
        return ". ".join(reasons) + "."
    
    def _assess_risk(self, entity: Dict, context: Dict) -> Dict:
        """Assess risk of not redacting"""
        entity_type = entity.get("type", "UNKNOWN")
        sensitivity = context.get("adjusted_sensitivity", "MEDIUM")
        
        risk_mapping = {
            "CRITICAL": {"level": "EXTREME", "score": 95, "consequence": "Immediate financial/identity fraud risk"},
            "HIGH": {"level": "HIGH", "score": 80, "consequence": "Significant privacy violation and potential harm"},
            "MEDIUM-HIGH": {"level": "ELEVATED", "score": 65, "consequence": "Privacy violation with re-identification potential"},
            "MEDIUM": {"level": "MODERATE", "score": 50, "consequence": "Privacy concern requiring redaction"},
            "LOW-MEDIUM": {"level": "LOW", "score": 30, "consequence": "Minor privacy concern"},
            "LOW": {"level": "MINIMAL", "score": 15, "consequence": "Contextual privacy consideration"}
        }
        
        return risk_mapping.get(sensitivity, risk_mapping["MEDIUM"])
    
    def _generate_recommendation(self, entity: Dict, legal_info: Dict, context: Dict) -> str:
        """Generate recommendation for handling"""
        entity_type = entity.get("type", "UNKNOWN")
        sensitivity = context.get("adjusted_sensitivity", "MEDIUM")
        
        if sensitivity in ["CRITICAL", "HIGH"]:
            return f"MANDATORY REDACTION: {entity_type} must be removed or replaced with synthetic data. Consider irreversible scrubbing for audit compliance."
        elif sensitivity in ["MEDIUM-HIGH", "MEDIUM"]:
            return f"RECOMMENDED REDACTION: {entity_type} should be redacted unless explicit consent exists. Document retention of original."
        else:
            return f"OPTIONAL REDACTION: {entity_type} may remain if document purpose requires it. Apply contextual judgment."
    
    def _format_human_readable(self, entity_type: str, reason: str, 
                               legal_info: Dict, context: Dict, confidence: float) -> str:
        """Format a human-readable explanation paragraph"""
        contexts = context.get("detected_contexts", [])
        context_str = f" in a {'/'.join(contexts)} document" if contexts else ""
        
        return (
            f"Redacted '{entity_type}' (confidence: {confidence*100:.0f}%){context_str}. "
            f"This data falls under {legal_info['category']} and is regulated by {legal_info['regulation']}. "
            f"{legal_info['reason']}. "
            f"Sensitivity level: {context.get('adjusted_sensitivity', legal_info['sensitivity'])}."
        )
    
    def _llm_enhance(self, entity: Dict, context: str) -> Optional[str]:
        """Enhance explanation using local LLM"""
        if self.llm != "ollama":
            return None
        
        try:
            import requests
            
            prompt = f"""Explain briefly (2-3 sentences) why the following data should be redacted for privacy:

Entity Type: {entity.get('type')}
Surrounding Context: "{context}"

Focus on: privacy risk, potential misuse, and compliance requirements."""

            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "mistral",
                    "prompt": prompt,
                    "stream": False
                },
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json().get("response", "")
        except:
            pass
        
        return None
    
    def generate_summary_report(self, explanations: List[Dict]) -> Dict[str, Any]:
        """Generate a summary report of all redaction decisions"""
        if not explanations:
            return {"total": 0, "summary": "No entities detected"}
        
        # Aggregate statistics
        by_type = {}
        by_sensitivity = {}
        total_risk_score = 0
        
        for exp in explanations:
            entity_type = exp["entity"]["type"]
            sensitivity = exp["legal_basis"]["context_sensitivity"]
            risk_score = exp["risk_assessment"]["score"]
            
            by_type[entity_type] = by_type.get(entity_type, 0) + 1
            by_sensitivity[sensitivity] = by_sensitivity.get(sensitivity, 0) + 1
            total_risk_score += risk_score
        
        avg_risk = total_risk_score / len(explanations)
        
        return {
            "total_entities": len(explanations),
            "by_entity_type": by_type,
            "by_sensitivity": by_sensitivity,
            "average_risk_score": round(avg_risk, 1),
            "highest_risk_entities": [
                exp for exp in explanations 
                if exp["risk_assessment"]["score"] >= 80
            ][:5],
            "compliance_note": self._generate_compliance_note(by_sensitivity)
        }
    
    def _generate_compliance_note(self, by_sensitivity: Dict) -> str:
        """Generate compliance advisory note"""
        critical_count = by_sensitivity.get("CRITICAL", 0)
        high_count = by_sensitivity.get("HIGH", 0)
        
        if critical_count > 0:
            return (
                f"CRITICAL: Document contains {critical_count} critical sensitivity item(s). "
                "Mandatory redaction required under applicable regulations. "
                "Recommend irreversible scrubbing and secure disposal of originals."
            )
        elif high_count > 0:
            return (
                f"IMPORTANT: Document contains {high_count} high sensitivity item(s). "
                "Redaction strongly recommended for compliance with DPDP Act and related regulations."
            )
        else:
            return (
                "Standard privacy considerations apply. "
                "Redaction recommended for external sharing."
            )
