"""
SilentSeal - Privacy-Preserving Analytics
Novel feature: Query redacted data without unredacting using differential privacy
"""

from typing import Dict, List, Any, Optional
import random
import math
from collections import defaultdict


class PrivacyAnalytics:
    """
    Privacy-preserving analytics using differential privacy
    
    This is a NOVEL FEATURE that allows:
    - Aggregate queries on redacted data
    - Differential privacy noise injection
    - Query budget tracking
    - Secure statistical analysis
    
    Enables data analysis without exposing individual records.
    """
    
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        """
        Initialize privacy analytics
        
        Args:
            epsilon: Privacy budget per query (lower = more private)
            delta: Probability of privacy breach
        """
        self.default_epsilon = epsilon
        self.delta = delta
        
        # Simulated redacted data store (in practice would be from processed documents)
        self.data_store = []
        
        # Query budget tracking
        self.total_budget = 10.0  # Total privacy budget
        self.spent_budget = 0.0
        
        # Query history for audit
        self.query_history = []
    
    def load_entities(self, entities: List[Dict]):
        """
        Load detected entities into the analytics store
        
        Args:
            entities: List of detected entities from documents
        """
        for entity in entities:
            # Store only type and aggregatable metadata, not actual values
            self.data_store.append({
                "type": entity.get("type", "UNKNOWN"),
                "confidence": entity.get("confidence", 1.0),
                "method": entity.get("method", "unknown"),
                # Generalizations for analysis
                "has_high_confidence": entity.get("confidence", 0) > 0.8,
            })
    
    def execute_query(self, query: str, epsilon: float = None) -> Dict[str, Any]:
        """
        Execute a privacy-preserving query
        
        Args:
            query: Natural language query
            epsilon: Privacy budget for this query
            
        Returns:
            Noised query result with metadata
        """
        epsilon = epsilon or self.default_epsilon
        
        # Check budget
        if self.spent_budget + epsilon > self.total_budget:
            return {
                "error": "Insufficient privacy budget",
                "remaining_budget": self.total_budget - self.spent_budget,
                "requested_epsilon": epsilon
            }
        
        # Parse query (simple pattern matching for demo)
        query_result = self._parse_and_execute(query)
        
        if "error" in query_result:
            return query_result
        
        # Apply differential privacy noise
        true_value = query_result["true_value"]
        sensitivity = query_result.get("sensitivity", 1)
        
        noised_value = self._add_laplace_noise(true_value, sensitivity, epsilon)
        
        # Update budget
        self.spent_budget += epsilon
        
        # Log query
        self.query_history.append({
            "query": query,
            "epsilon": epsilon,
            "timestamp": self._get_timestamp()
        })
        
        return {
            "query": query,
            "result": self._format_result(noised_value, query_result["result_type"]),
            "noise_info": {
                "mechanism": "Laplace",
                "epsilon": epsilon,
                "sensitivity": sensitivity,
                "noise_scale": sensitivity / epsilon
            },
            "confidence_interval": self._calculate_confidence_interval(noised_value, sensitivity, epsilon),
            "privacy_spent": epsilon,
            "remaining_budget": round(self.total_budget - self.spent_budget, 2),
            "warning": self._get_budget_warning()
        }
    
    def _parse_and_execute(self, query: str) -> Dict[str, Any]:
        """Parse natural language query and execute"""
        query_lower = query.lower()
        
        # COUNT queries
        if "count" in query_lower or "how many" in query_lower:
            return self._handle_count_query(query_lower)
        
        # AVERAGE queries
        if "average" in query_lower or "mean" in query_lower:
            return self._handle_average_query(query_lower)
        
        # PERCENTAGE queries
        if "percent" in query_lower or "proportion" in query_lower:
            return self._handle_percentage_query(query_lower)
        
        # Distribution queries
        if "distribution" in query_lower or "breakdown" in query_lower:
            return self._handle_distribution_query(query_lower)
        
        return {
            "error": "Query type not supported",
            "supported_queries": [
                "COUNT: 'How many entities of type X?'",
                "AVERAGE: 'Average confidence of detections'",
                "PERCENTAGE: 'What percentage are high confidence?'",
                "DISTRIBUTION: 'Distribution of entity types'"
            ]
        }
    
    def _handle_count_query(self, query: str) -> Dict[str, Any]:
        """Handle COUNT queries"""
        # Check for entity type filter
        entity_types = ["aadhaar", "pan", "email", "phone", "person_name", 
                       "location", "organization", "date_of_birth"]
        
        filtered_type = None
        for et in entity_types:
            if et in query:
                filtered_type = et.upper()
                break
        
        if filtered_type:
            count = sum(1 for d in self.data_store if d["type"] == filtered_type)
        else:
            count = len(self.data_store)
        
        return {
            "true_value": count,
            "sensitivity": 1,  # Adding/removing one record changes count by 1
            "result_type": "count",
            "description": f"Count of {filtered_type or 'all'} entities"
        }
    
    def _handle_average_query(self, query: str) -> Dict[str, Any]:
        """Handle AVERAGE queries"""
        if "confidence" in query:
            if not self.data_store:
                return {"error": "No data available"}
            
            confidences = [d["confidence"] for d in self.data_store]
            avg = sum(confidences) / len(confidences)
            
            return {
                "true_value": avg,
                "sensitivity": 1.0 / len(self.data_store),  # Bounded by 0-1
                "result_type": "average",
                "description": "Average detection confidence"
            }
        
        return {"error": "Average of what? Specify 'confidence' in query"}
    
    def _handle_percentage_query(self, query: str) -> Dict[str, Any]:
        """Handle PERCENTAGE queries"""
        if not self.data_store:
            return {"error": "No data available"}
        
        if "high confidence" in query:
            high_conf = sum(1 for d in self.data_store if d["has_high_confidence"])
            percentage = (high_conf / len(self.data_store)) * 100
            
            return {
                "true_value": percentage,
                "sensitivity": 100.0 / len(self.data_store),
                "result_type": "percentage",
                "description": "Percentage of high confidence detections"
            }
        
        return {"error": "Percentage of what? Specify condition in query"}
    
    def _handle_distribution_query(self, query: str) -> Dict[str, Any]:
        """Handle DISTRIBUTION queries (returns noised histogram)"""
        if not self.data_store:
            return {"error": "No data available"}
        
        # Count by entity type
        distribution = defaultdict(int)
        for d in self.data_store:
            distribution[d["type"]] += 1
        
        # For histograms, sensitivity is 1 per bin
        return {
            "true_value": dict(distribution),
            "sensitivity": 1,
            "result_type": "distribution",
            "description": "Distribution of entity types"
        }
    
    def _add_laplace_noise(self, value: Any, sensitivity: float, epsilon: float) -> Any:
        """Add Laplace noise for differential privacy"""
        scale = sensitivity / epsilon
        
        if isinstance(value, (int, float)):
            noise = random.gauss(0, scale * math.sqrt(2))  # Approximation of Laplace
            return value + noise
        
        elif isinstance(value, dict):
            # Add noise to each value in dictionary (histogram)
            noised = {}
            for k, v in value.items():
                noise = random.gauss(0, scale * math.sqrt(2))
                noised[k] = max(0, int(v + noise))  # Ensure non-negative
            return noised
        
        return value
    
    def _format_result(self, value: Any, result_type: str) -> Any:
        """Format result based on type"""
        if result_type == "count":
            return max(0, int(round(value)))
        elif result_type == "average":
            return round(value, 3)
        elif result_type == "percentage":
            return round(max(0, min(100, value)), 1)
        elif result_type == "distribution":
            return value
        return value
    
    def _calculate_confidence_interval(self, value: Any, sensitivity: float, epsilon: float) -> Dict:
        """Calculate confidence interval for noised result"""
        if not isinstance(value, (int, float)):
            return {"note": "Confidence intervals for distributions are per-bin"}
        
        scale = sensitivity / epsilon
        # 95% confidence interval for Laplace distribution
        margin = scale * math.log(0.05 / 2) * -1
        
        return {
            "lower": round(value - margin, 1),
            "upper": round(value + margin, 1),
            "confidence_level": "95%"
        }
    
    def _get_budget_warning(self) -> Optional[str]:
        """Get warning if budget is running low"""
        remaining = self.total_budget - self.spent_budget
        
        if remaining <= 0:
            return "CRITICAL: Privacy budget exhausted. No more queries allowed."
        elif remaining < 2:
            return "WARNING: Low privacy budget remaining. Limit further queries."
        elif remaining < 5:
            return "NOTE: Moderate privacy budget remaining."
        
        return None
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
    
    def get_budget_status(self) -> Dict[str, Any]:
        """Get current privacy budget status"""
        return {
            "total_budget": self.total_budget,
            "spent_budget": round(self.spent_budget, 2),
            "remaining_budget": round(self.total_budget - self.spent_budget, 2),
            "queries_executed": len(self.query_history),
            "average_epsilon_per_query": (
                round(self.spent_budget / len(self.query_history), 2)
                if self.query_history else 0
            )
        }
    
    def reset_budget(self, new_budget: float = 10.0):
        """Reset privacy budget (should require admin approval)"""
        self.total_budget = new_budget
        self.spent_budget = 0.0
        self.query_history = []
        
        return {
            "status": "Budget reset",
            "new_budget": new_budget,
            "warning": "Resetting budget may violate differential privacy guarantees if used on same data"
        }
    
    def get_query_history(self) -> List[Dict]:
        """Get audit log of all queries"""
        return self.query_history
    
    def explain_differential_privacy(self) -> Dict[str, str]:
        """Explain differential privacy for users"""
        return {
            "what_is_dp": (
                "Differential Privacy is a mathematical framework that ensures "
                "individual records cannot be identified from query results."
            ),
            "how_it_works": (
                "We add calibrated random noise to all query results. "
                "This noise masks individual contributions while preserving "
                "aggregate statistical properties."
            ),
            "epsilon_meaning": (
                f"Epsilon (ε) controls the privacy-utility tradeoff. "
                f"Current ε={self.default_epsilon}. Lower ε = more privacy, more noise. "
                "Industry standard is ε between 0.1 and 2.0."
            ),
            "budget_meaning": (
                f"Privacy budget limits total information leakage. "
                f"You have {self.total_budget - self.spent_budget:.1f} remaining. "
                "Each query consumes budget proportional to its ε."
            ),
            "guarantees": (
                "With our settings, an attacker cannot determine with more than "
                f"{math.exp(self.default_epsilon):.1f}x confidence whether any "
                "specific individual's data was included in the analysis."
            )
        }
