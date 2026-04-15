"""
SilentSeal - Re-identification Risk Score Calculator
Novel feature: Calculates privacy risk based on quasi-identifiers and k-anonymity
"""

import math
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict
import hashlib


class RiskScoreCalculator:
    """
    Calculates re-identification risk for documents
    
    Based on:
    - Quasi-identifier combinations (age + location + gender)
    - k-anonymity estimation
    - Uniqueness scoring
    
    This is a NOVEL FEATURE not found in standard redaction tools.
    """
    
    # Quasi-identifier categories
    QUASI_IDENTIFIERS = {
        "demographic": ["PERSON_NAME", "DATE_OF_BIRTH", "LOCATION"],
        "contact": ["EMAIL", "PHONE", "IP_ADDRESS"],
        "financial": ["PAN", "AADHAAR", "BANK_ACCOUNT", "CREDIT_CARD"],
        "organizational": ["ORGANIZATION", "DRIVING_LICENSE", "PASSPORT"]
    }
    
    # Risk weights for different entity types
    RISK_WEIGHTS = {
        "AADHAAR": 1.0,      # Unique identifier
        "PAN": 0.95,          # Unique identifier
        "PASSPORT": 0.95,     # Unique identifier
        "EMAIL": 0.9,         # Often unique
        "PHONE": 0.85,        # Often unique
        "CREDIT_CARD": 0.95,  # Unique financial identifier
        "PERSON_NAME": 0.7,   # Common names less risky
        "DATE_OF_BIRTH": 0.6, # Combined with others is risky
        "LOCATION": 0.5,      # Population dependent
        "ORGANIZATION": 0.3,  # Context dependent
        "IP_ADDRESS": 0.7,    # Can be dynamic
        "DRIVING_LICENSE": 0.9,
        "BANK_ACCOUNT": 0.95,
        "IFSC": 0.2           # Public information
    }
    
    # Population estimates for k-anonymity (India focused)
    POPULATION_ESTIMATES = {
        "national": 1_400_000_000,
        "state": 100_000_000,
        "city": 10_000_000,
        "district": 1_000_000,
        "locality": 10_000
    }
    
    def __init__(self):
        pass
    
    def calculate(self, entities: List[Dict], full_text: str) -> Dict[str, Any]:
        """
        Calculate comprehensive re-identification risk score
        
        Args:
            entities: List of detected entities
            full_text: Full document text for context analysis
            
        Returns:
            Risk assessment with score, level, and recommendations
        """
        if not entities:
            return {
                "score": 0.0,
                "level": "MINIMAL",
                "k_anonymity": float('inf'),
                "quasi_identifiers": [],
                "direct_identifiers": [],
                "explanation": "No sensitive entities detected.",
                "recommendations": []
            }
        
        # Categorize entities
        direct_identifiers = []
        quasi_identifiers = []
        
        for entity in entities:
            entity_type = entity.get("type", "")
            
            # Direct identifiers (unique by themselves)
            if entity_type in ["AADHAAR", "PAN", "PASSPORT", "CREDIT_CARD", "DRIVING_LICENSE"]:
                direct_identifiers.append(entity)
            else:
                quasi_identifiers.append(entity)
        
        # Calculate base risk from direct identifiers
        direct_risk = self._calculate_direct_risk(direct_identifiers)
        
        # Calculate quasi-identifier combination risk
        quasi_risk, dangerous_combos = self._calculate_quasi_risk(quasi_identifiers)
        
        # Estimate k-anonymity
        k_anonymity = self._estimate_k_anonymity(entities)
        
        # Context-based risk adjustments
        context_risk = self._analyze_context(entities, full_text)
        
        # Combine risks (weighted average with ceiling)
        combined_risk = min(
            direct_risk * 0.4 + quasi_risk * 0.3 + context_risk * 0.3,
            1.0
        )
        
        # Adjust based on k-anonymity
        if k_anonymity <= 2:
            combined_risk = min(combined_risk + 0.3, 1.0)
        elif k_anonymity <= 5:
            combined_risk = min(combined_risk + 0.1, 1.0)
        
        # Determine risk level
        risk_level = self._determine_risk_level(combined_risk)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            direct_identifiers, 
            quasi_identifiers, 
            dangerous_combos, 
            k_anonymity
        )
        
        return {
            "score": round(combined_risk * 100, 1),
            "level": risk_level,
            "k_anonymity": k_anonymity,
            "quasi_identifiers": [self._summarize_entity(e) for e in quasi_identifiers],
            "direct_identifiers": [self._summarize_entity(e) for e in direct_identifiers],
            "dangerous_combinations": dangerous_combos,
            "explanation": self._generate_explanation(combined_risk, k_anonymity, len(direct_identifiers)),
            "recommendations": recommendations
        }
    
    def _calculate_direct_risk(self, direct_identifiers: List[Dict]) -> float:
        """Calculate risk from direct identifiers"""
        if not direct_identifiers:
            return 0.0
        
        # Any direct identifier is high risk
        max_weight = max(
            self.RISK_WEIGHTS.get(e.get("type", ""), 0.5) 
            for e in direct_identifiers
        )
        
        # More direct identifiers = higher risk
        count_factor = min(len(direct_identifiers) * 0.1, 0.3)
        
        return min(max_weight + count_factor, 1.0)
    
    def _calculate_quasi_risk(self, quasi_identifiers: List[Dict]) -> Tuple[float, List[Dict]]:
        """Calculate risk from quasi-identifier combinations"""
        if not quasi_identifiers:
            return 0.0, []
        
        dangerous_combinations = []
        
        # Group by category
        entity_types = set(e.get("type", "") for e in quasi_identifiers)
        
        # Check for dangerous combinations
        danger_patterns = [
            {"required": {"DATE_OF_BIRTH", "LOCATION"}, "risk": 0.7, "name": "DOB + Location"},
            {"required": {"PERSON_NAME", "LOCATION"}, "risk": 0.6, "name": "Name + Location"},
            {"required": {"PERSON_NAME", "DATE_OF_BIRTH"}, "risk": 0.65, "name": "Name + DOB"},
            {"required": {"PERSON_NAME", "DATE_OF_BIRTH", "LOCATION"}, "risk": 0.9, "name": "Name + DOB + Location"},
            {"required": {"PERSON_NAME", "ORGANIZATION"}, "risk": 0.5, "name": "Name + Organization"},
            {"required": {"PHONE", "PERSON_NAME"}, "risk": 0.8, "name": "Phone + Name"},
            {"required": {"EMAIL", "PERSON_NAME"}, "risk": 0.8, "name": "Email + Name"},
        ]
        
        max_risk = 0.0
        
        for pattern in danger_patterns:
            if pattern["required"].issubset(entity_types):
                dangerous_combinations.append({
                    "combination": list(pattern["required"]),
                    "risk": pattern["risk"],
                    "name": pattern["name"]
                })
                max_risk = max(max_risk, pattern["risk"])
        
        # Base risk from individual quasi-identifiers
        if not dangerous_combinations:
            individual_risk = sum(
                self.RISK_WEIGHTS.get(e.get("type", ""), 0.3) 
                for e in quasi_identifiers
            ) / len(quasi_identifiers)
            max_risk = individual_risk * 0.5
        
        return max_risk, dangerous_combinations
    
    def _estimate_k_anonymity(self, entities: List[Dict]) -> int:
        """
        Estimate k-anonymity based on entity uniqueness
        
        k-anonymity: minimum number of people with the same combination of attributes
        Lower k = higher risk
        """
        entity_types = set(e.get("type", "") for e in entities)
        
        # Start with national population
        k = self.POPULATION_ESTIMATES["national"]
        
        # Each identifier reduces the anonymity set
        for entity in entities:
            entity_type = entity.get("type", "")
            
            if entity_type in ["AADHAAR", "PAN", "PASSPORT"]:
                k = 1  # These are unique
                break
            elif entity_type == "EMAIL":
                k = min(k, 1)  # Usually unique
            elif entity_type == "PHONE":
                k = min(k, 1)  # Usually unique
            elif entity_type == "LOCATION":
                k = min(k, self.POPULATION_ESTIMATES["city"])
            elif entity_type == "DATE_OF_BIRTH":
                k = k // 365  # Divide by days in year
            elif entity_type == "PERSON_NAME":
                k = k // 1000  # Assume ~1000 people share common names
            elif entity_type == "ORGANIZATION":
                k = min(k, 100000)  # Organization employee count estimate
        
        return max(k, 1)
    
    def _analyze_context(self, entities: List[Dict], full_text: str) -> float:
        """Analyze document context for additional risk factors"""
        risk = 0.0
        
        # Check for medical context (higher privacy requirements)
        medical_terms = ["patient", "diagnosis", "treatment", "hospital", "doctor", "prescription"]
        if any(term in full_text.lower() for term in medical_terms):
            risk += 0.2
        
        # Check for financial context
        financial_terms = ["salary", "income", "bank", "account", "tax", "payment"]
        if any(term in full_text.lower() for term in financial_terms):
            risk += 0.15
        
        # Check for employment context
        employment_terms = ["employee", "hr", "performance", "appraisal", "salary"]
        if any(term in full_text.lower() for term in employment_terms):
            risk += 0.1
        
        # Entity density (many entities close together)
        if len(entities) > 10:
            risk += 0.1
        
        return min(risk, 0.5)
    
    def _determine_risk_level(self, score: float) -> str:
        """Convert numeric score to risk level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_recommendations(self, direct: List[Dict], quasi: List[Dict], 
                                   combos: List[Dict], k: int) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if direct:
            direct_types = set(e.get("type", "") for e in direct)
            recommendations.append(
                f"CRITICAL: Redact all direct identifiers ({', '.join(direct_types)})"
            )
        
        if k <= 5:
            recommendations.append(
                f"WARNING: Low k-anonymity (k={k}). Consider generalizing quasi-identifiers."
            )
        
        for combo in combos[:3]:  # Top 3 dangerous combos
            recommendations.append(
                f"DANGER: {combo['name']} combination creates high re-identification risk ({combo['risk']*100:.0f}%)"
            )
        
        # Specific recommendations
        quasi_types = set(e.get("type", "") for e in quasi)
        
        if "DATE_OF_BIRTH" in quasi_types:
            recommendations.append(
                "TIP: Generalize dates (e.g., '1990-05-15' → '1990' or 'Age: 30-35')"
            )
        
        if "LOCATION" in quasi_types:
            recommendations.append(
                "TIP: Generalize locations (e.g., 'Chennai, Tamil Nadu' → 'South India')"
            )
        
        return recommendations
    
    def _generate_explanation(self, score: float, k: int, direct_count: int) -> str:
        """Generate human-readable explanation of risk score"""
        if direct_count > 0:
            return (
                f"Document contains {direct_count} unique identifier(s) that can directly identify individuals. "
                f"Even after redaction, verify that no copies remain in metadata."
            )
        
        if k <= 1:
            return (
                "The combination of quasi-identifiers in this document is unique enough to "
                "identify a specific individual with high probability."
            )
        elif k <= 5:
            return (
                f"With k-anonymity of {k}, this individual is among only {k} people sharing "
                "these combined attributes. This poses significant re-identification risk."
            )
        else:
            return (
                f"Risk score of {score*100:.0f}% based on quasi-identifier analysis. "
                "Recommend redaction of highlighted entities before sharing."
            )
    
    def _summarize_entity(self, entity: Dict) -> Dict:
        """Create a summary of entity without exposing actual value"""
        value = entity.get("text", "")
        return {
            "type": entity.get("type", ""),
            "preview": value[:3] + "***" if len(value) > 3 else "***",
            "confidence": entity.get("confidence", 0)
        }
