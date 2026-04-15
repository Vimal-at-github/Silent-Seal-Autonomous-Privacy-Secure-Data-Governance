"""
SilentSeal - Adversarial Robustness Tester
Novel feature: Tests if redacted documents are resistant to de-anonymization attacks
"""

from typing import Dict, List, Any, Tuple
import re
from collections import defaultdict


class AdversarialTester:
    """
    Tests redaction robustness against adversarial attacks
    
    This is a NOVEL FEATURE that simulates attacker scenarios:
    - Context-based prediction attacks
    - Pattern/format leakage analysis
    - Metadata exposure checks
    - Cross-reference attacks
    
    Provides a Robustness Score (0-100) with specific vulnerabilities.
    """
    
    def __init__(self):
        # Common name patterns for prediction
        self.common_names = {
            "Dr.": ["Sharma", "Gupta", "Kumar", "Singh", "Reddy"],
            "Mr.": ["Patel", "Shah", "Mehta", "Joshi", "Desai"],
            "Mrs.": ["Devi", "Kumari", "Rani", "Kaur", "Nair"],
            "Prof.": ["Iyer", "Rao", "Chatterjee", "Banerjee", "Sen"]
        }
        
        # Predictable patterns
        self.predictable_patterns = {
            "hospital_names": [
                "Apollo", "Fortis", "Max", "AIIMS", "Medanta", "Manipal",
                "Narayana", "Columbia Asia", "Lilavati", "Breach Candy"
            ],
            "bank_names": [
                "SBI", "HDFC", "ICICI", "Axis", "Kotak", "PNB",
                "Bank of Baroda", "Canara", "Union Bank", "IndusInd"
            ],
            "city_patterns": [
                "Chennai", "Mumbai", "Delhi", "Bangalore", "Hyderabad",
                "Kolkata", "Pune", "Ahmedabad", "Jaipur", "Lucknow"
            ]
        }
    
    def test(self, original_text: str, entities: List[Dict], is_synthetic: bool = False) -> Dict[str, Any]:
        """
        Run comprehensive adversarial tests on document
        
        Args:
            original_text: Original document text (before redaction)
            entities: List of detected entities
            is_synthetic: Whether synthetic replacement was used
            
        Returns:
            Robustness report with score and vulnerabilities
        """
        vulnerabilities = []
        
        # Test 1: Context prediction attack
        context_vulns = self._test_context_prediction(original_text, entities)
        vulnerabilities.extend(context_vulns)
        
        # Test 2: Format leakage attack
        format_vulns = self._test_format_leakage(original_text, entities)
        vulnerabilities.extend(format_vulns)
        
        # Test 3: Partial information attack
        partial_vulns = self._test_partial_information(original_text, entities)
        vulnerabilities.extend(partial_vulns)
        
        # Test 4: Cross-reference attack simulation
        crossref_vulns = self._test_cross_reference(original_text, entities)
        vulnerabilities.extend(crossref_vulns)
        
        # Test 5: Metadata exposure check
        metadata_vulns = self._test_metadata_exposure(original_text, entities)
        vulnerabilities.extend(metadata_vulns)
        
        # Calculate robustness score
        robustness_score = self._calculate_robustness_score(vulnerabilities)
        
        # Novel Feature: Reward synthetic replacement
        # It's much harder to guess if data is fake than if it's just a black box
        if is_synthetic and len(entities) > 0:
            robustness_score = min(100, robustness_score + 20)
            # Remove minor format leakage vulnerabilities if synthetic fakes are used
            # because synthetic data replaces the format leakage with a common one
            vulnerabilities = [v for v in vulnerabilities if v.get("type") != "FORMAT_LEAKAGE" or v.get("severity") != "LOW"]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities)
        
        return {
            "robustness_score": robustness_score,
            "grade": self._score_to_grade(robustness_score),
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "attack_simulations": {
                "context_prediction": len(context_vulns),
                "format_leakage": len(format_vulns),
                "partial_information": len(partial_vulns),
                "cross_reference": len(crossref_vulns),
                "metadata_exposure": len(metadata_vulns)
            },
            "recommendations": recommendations,
            "summary": self._generate_summary(robustness_score, vulnerabilities)
        }
    
    def _test_context_prediction(self, text: str, entities: List[Dict]) -> List[Dict]:
        """Test if redacted values can be predicted from surrounding context"""
        vulnerabilities = []
        
        for entity in entities:
            entity_text = entity.get("text", "")
            entity_type = entity.get("type", "")
            start = entity.get("start", 0)
            end = entity.get("end", len(entity_text))
            
            # Get context (100 chars before and after)
            context_start = max(0, start - 100)
            context_end = min(len(text), end + 100)
            context = text[context_start:context_end]
            
            # Check for predictable patterns
            predictions = self._predict_from_context(entity_type, context, entity_text)
            
            if predictions:
                vulnerabilities.append({
                    "type": "CONTEXT_PREDICTION",
                    "severity": "HIGH" if predictions[0]["confidence"] > 0.3 else "MEDIUM",
                    "entity_type": entity_type,
                    "context_snippet": context.replace(entity_text, "[REDACTED]")[:100] + "...",
                    "predictions": predictions[:3],  # Top 3 predictions
                    "recommendation": f"Redact additional context around {entity_type}"
                })
        
        return vulnerabilities
    
    def _predict_from_context(self, entity_type: str, context: str, actual_value: str) -> List[Dict]:
        """Simulate prediction attack based on context"""
        predictions = []
        
        if entity_type == "PERSON_NAME":
            # Check for title indicators
            for title, common_names in self.common_names.items():
                if title in context:
                    for name in common_names:
                        # Simple similarity check
                        if len(actual_value) > 0 and actual_value[0].upper() == name[0]:
                            predictions.append({
                                "predicted": name,
                                "confidence": 0.35,
                                "basis": f"Common name following '{title}'"
                            })
                        else:
                            predictions.append({
                                "predicted": name,
                                "confidence": 0.15,
                                "basis": f"Common name following '{title}'"
                            })
        
        elif entity_type == "ORGANIZATION":
            # Check for organization context
            if any(term in context.lower() for term in ["hospital", "medical", "clinic"]):
                for hospital in self.predictable_patterns["hospital_names"]:
                    predictions.append({
                        "predicted": hospital,
                        "confidence": 0.2,
                        "basis": "Common hospital name in medical context"
                    })
            elif any(term in context.lower() for term in ["bank", "account", "payment"]):
                for bank in self.predictable_patterns["bank_names"]:
                    predictions.append({
                        "predicted": bank,
                        "confidence": 0.2,
                        "basis": "Common bank name in financial context"
                    })
        
        elif entity_type == "LOCATION":
            for city in self.predictable_patterns["city_patterns"]:
                if city.lower() in actual_value.lower():
                    predictions.append({
                        "predicted": city,
                        "confidence": 0.4,
                        "basis": "Common city name matched"
                    })
        
        # Sort by confidence
        predictions.sort(key=lambda x: x["confidence"], reverse=True)
        return predictions
    
    def _test_format_leakage(self, text: str, entities: List[Dict]) -> List[Dict]:
        """Test if redacted value format leaks information"""
        vulnerabilities = []
        
        for entity in entities:
            entity_text = entity.get("text", "")
            entity_type = entity.get("type", "")
            
            # Check format patterns
            if entity_type == "PHONE":
                # Phone format reveals telecom provider region
                if entity_text.startswith("+91 9"):
                    vulnerabilities.append({
                        "type": "FORMAT_LEAKAGE",
                        "severity": "LOW",
                        "entity_type": entity_type,
                        "detail": "Phone prefix '9' indicates specific operator range",
                        "recommendation": "Redact complete number including prefix"
                    })
            
            elif entity_type == "EMAIL":
                # Email domain reveals organization
                if "@" in entity_text:
                    domain = entity_text.split("@")[1]
                    if not domain.endswith(("gmail.com", "yahoo.com", "outlook.com")):
                        vulnerabilities.append({
                            "type": "FORMAT_LEAKAGE",
                            "severity": "MEDIUM",
                            "entity_type": entity_type,
                            "detail": f"Email domain '{domain}' reveals organization affiliation",
                            "recommendation": "Redact entire email including domain"
                        })
            
            elif entity_type == "PAN":
                # 4th character reveals holder type
                if len(entity_text) >= 4:
                    holder_type_map = {
                        "P": "Individual", "C": "Company", "H": "HUF",
                        "F": "Firm", "T": "Trust", "G": "Government"
                    }
                    holder = holder_type_map.get(entity_text[3], "Unknown")
                    vulnerabilities.append({
                        "type": "FORMAT_LEAKAGE",
                        "severity": "LOW",
                        "entity_type": entity_type,
                        "detail": f"PAN 4th character reveals holder type: {holder}",
                        "recommendation": "Complete redaction prevents this leak"
                    })
        
        return vulnerabilities
    
    def _test_partial_information(self, text: str, entities: List[Dict]) -> List[Dict]:
        """Test for partial information that could aid identification"""
        vulnerabilities = []
        
        # Check for related entities that together increase risk
        entity_types = [e.get("type") for e in entities]
        
        # Dangerous combinations
        if "PERSON_NAME" in entity_types and "DATE_OF_BIRTH" in entity_types:
            vulnerabilities.append({
                "type": "PARTIAL_INFORMATION",
                "severity": "HIGH",
                "entity_type": "COMBINATION",
                "detail": "Name + DOB combination significantly narrows identification",
                "recommendation": "Consider removing DOB or generalizing to age range"
            })
        
        if "PERSON_NAME" in entity_types and "LOCATION" in entity_types and "ORGANIZATION" in entity_types:
            vulnerabilities.append({
                "type": "PARTIAL_INFORMATION",
                "severity": "HIGH",
                "entity_type": "COMBINATION",
                "detail": "Name + Location + Organization creates unique fingerprint",
                "recommendation": "Generalize location or remove organization reference"
            })
        
        return vulnerabilities
    
    def _test_cross_reference(self, text: str, entities: List[Dict]) -> List[Dict]:
        """Simulate cross-reference attack against public databases"""
        vulnerabilities = []
        
        for entity in entities:
            entity_type = entity.get("type", "")
            
            # Check entities that can be looked up
            if entity_type == "ORGANIZATION":
                vulnerabilities.append({
                    "type": "CROSS_REFERENCE",
                    "severity": "MEDIUM",
                    "entity_type": entity_type,
                    "detail": "Organization names can be cross-referenced with employee directories",
                    "attack_vector": "LinkedIn, company websites, MCA filings",
                    "recommendation": "Remove or generalize organization references"
                })
            
            if entity_type in ["PHONE", "EMAIL"]:
                vulnerabilities.append({
                    "type": "CROSS_REFERENCE",
                    "severity": "HIGH",
                    "entity_type": entity_type,
                    "detail": f"{entity_type} can be searched in public databases",
                    "attack_vector": "Truecaller, social media, OSINT tools",
                    "recommendation": f"Ensure complete {entity_type} redaction"
                })
        
        return vulnerabilities
    
    def _test_metadata_exposure(self, text: str, entities: List[Dict]) -> List[Dict]:
        """Check for metadata-based information leakage"""
        vulnerabilities = []
        
        # Check for patterns that suggest metadata issues
        metadata_patterns = [
            (r"Author:\s*\w+", "Document author field"),
            (r"Created:\s*\d{4}", "Creation date metadata"),
            (r"Modified:\s*\d{4}", "Modification date metadata"),
            (r"Subject:\s*\w+", "Document subject field"),
        ]
        
        for pattern, description in metadata_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                vulnerabilities.append({
                    "type": "METADATA_EXPOSURE",
                    "severity": "MEDIUM",
                    "detail": f"Text suggests {description} may contain identifying information",
                    "recommendation": "Scrub document metadata before sharing"
                })
        
        return vulnerabilities
    
    def _calculate_robustness_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate overall robustness score (0-100)"""
        base_score = 100
        
        severity_penalties = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3
        }
        
        # Group vulnerabilities by type to avoid over-penalizing for many occurrences
        # of the same risk type (e.g., 50 emails shouldn't necessarily mean score 0)
        by_type = defaultdict(list)
        for vuln in vulnerabilities:
            by_type[vuln.get("type", "UNKNOWN")].append(vuln)
            
        for v_type, volns in by_type.items():
            # Get max severity for this type
            max_severity = "LOW"
            severities = [v.get("severity", "LOW") for v in volns]
            if "CRITICAL" in severities: max_severity = "CRITICAL"
            elif "HIGH" in severities: max_severity = "HIGH"
            elif "MEDIUM" in severities: max_severity = "MEDIUM"
            
            penalty = severity_penalties.get(max_severity, 5)
            
            # Add a small "volume" penalty for multiple occurrences (max 10 extra points)
            volume_penalty = min(10, len(volns) // 2) 
            
            base_score -= (penalty + volume_penalty)
        
        return max(5, base_score) # Ensure it doesn't hit 0 easily unless truly critical
    
    def _score_to_grade(self, score: int) -> str:
        """Convert score to letter grade"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = set()
        
        for vuln in vulnerabilities:
            if "recommendation" in vuln:
                recommendations.add(vuln["recommendation"])
        
        # Add general recommendations based on vulnerability types
        vuln_types = set(v.get("type") for v in vulnerabilities)
        
        if "CONTEXT_PREDICTION" in vuln_types:
            recommendations.add("Expand redaction zones to include surrounding context")
        
        if "CROSS_REFERENCE" in vuln_types:
            recommendations.add("Consider synthetic data replacement instead of black-box redaction")
        
        if "METADATA_EXPOSURE" in vuln_types:
            recommendations.add("Run metadata scrubbing on final document")
        
        return list(recommendations)
    
    def _generate_summary(self, score: int, vulnerabilities: List[Dict]) -> str:
        """Generate human-readable summary"""
        grade = self._score_to_grade(score)
        
        if score >= 90:
            return f"EXCELLENT ({grade}): Document redaction is robust against common attacks. {len(vulnerabilities)} minor findings."
        elif score >= 70:
            return f"GOOD ({grade}): Redaction is reasonable but has {len(vulnerabilities)} vulnerability(s) that should be addressed."
        elif score >= 50:
            return f"FAIR ({grade}): Significant vulnerabilities detected. {len(vulnerabilities)} issues require attention before sharing."
        else:
            return f"POOR ({grade}): Document has critical vulnerabilities. Not recommended for external sharing. Fix {len(vulnerabilities)} issue(s)."
