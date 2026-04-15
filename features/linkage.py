"""
SilentSeal - Cross-Document Linkage Detection
Novel feature: Detects if multiple documents together can re-identify individuals
"""

from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict
import hashlib


class CrossDocumentLinkage:
    """
    Detects privacy risks when multiple documents are shared together
    
    This is a NOVEL FEATURE that analyzes:
    - Entity matches across documents
    - Combined re-identification risk
    - Linkage graph construction
    
    Critical for organizations sharing multiple documents externally.
    """
    
    def __init__(self):
        # Entity types that strongly indicate same individual
        self.strong_linkage_types = {
            "AADHAAR", "PAN", "PASSPORT", "EMAIL", "PHONE", "DRIVING_LICENSE"
        }
        
        # Entity types that indicate possible linkage
        self.weak_linkage_types = {
            "PERSON_NAME", "DATE_OF_BIRTH", "BANK_ACCOUNT"
        }
        
        # Context types that narrow identification
        self.context_types = {
            "LOCATION", "ORGANIZATION"
        }
    
    def detect(self, documents: List[Dict]) -> Dict[str, Any]:
        """
        Detect linkage risks across multiple documents
        
        Args:
            documents: List of {"doc_id": str, "entities": List[Dict]}
            
        Returns:
            Linkage analysis with risks and recommendations
        """
        if len(documents) < 2:
            return {
                "linkages": [],
                "combined_risk": 0,
                "recommendations": ["Need at least 2 documents for linkage analysis"]
            }
        
        # Extract entity fingerprints from each document
        doc_fingerprints = {}
        for doc in documents:
            doc_id = doc["doc_id"]
            entities = doc["entities"]
            doc_fingerprints[doc_id] = self._create_fingerprints(entities)
        
        # Find matching entities across documents
        linkages = self._find_linkages(doc_fingerprints)
        
        # Analyze combined risk
        combined_risk = self._calculate_combined_risk(linkages, documents)
        
        # Generate linkage graph
        linkage_graph = self._build_linkage_graph(linkages)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(linkages, combined_risk)
        
        return {
            "documents_analyzed": len(documents),
            "linkages": linkages,
            "combined_risk": combined_risk,
            "linkage_graph": linkage_graph,
            "individual_clusters": self._find_individual_clusters(linkage_graph),
            "recommendations": recommendations,
            "summary": self._generate_summary(linkages, combined_risk)
        }
    
    def _create_fingerprints(self, entities: List[Dict]) -> Dict[str, List[Dict]]:
        """Create entity fingerprints for a document"""
        fingerprints = defaultdict(list)
        
        for entity in entities:
            entity_type = entity.get("type", "")
            entity_text = entity.get("text", "")
            
            # Normalize text for matching
            normalized = self._normalize_text(entity_text, entity_type)
            
            # Create hash for privacy
            entity_hash = hashlib.sha256(normalized.encode()).hexdigest()[:16]
            
            fingerprints[entity_type].append({
                "original": entity_text,
                "normalized": normalized,
                "hash": entity_hash,
                "confidence": entity.get("confidence", 1.0)
            })
        
        return dict(fingerprints)
    
    def _normalize_text(self, text: str, entity_type: str) -> str:
        """Normalize text for consistent matching"""
        text = text.strip().lower()
        
        if entity_type == "PHONE":
            # Remove formatting
            text = ''.join(c for c in text if c.isdigit())
            # Remove country code
            if text.startswith("91") and len(text) > 10:
                text = text[2:]
        
        elif entity_type == "AADHAAR":
            # Remove spaces
            text = text.replace(" ", "")
        
        elif entity_type == "PERSON_NAME":
            # Remove titles and normalize
            titles = ["mr.", "mrs.", "ms.", "dr.", "prof.", "shri", "smt."]
            for title in titles:
                text = text.replace(title, "").strip()
        
        return text
    
    def _find_linkages(self, doc_fingerprints: Dict[str, Dict]) -> List[Dict]:
        """Find matching entities across documents"""
        linkages = []
        doc_ids = list(doc_fingerprints.keys())
        
        # Compare each pair of documents
        for i in range(len(doc_ids)):
            for j in range(i + 1, len(doc_ids)):
                doc1_id = doc_ids[i]
                doc2_id = doc_ids[j]
                doc1_fp = doc_fingerprints[doc1_id]
                doc2_fp = doc_fingerprints[doc2_id]
                
                # Find matching entities
                matches = self._compare_fingerprints(doc1_fp, doc2_fp)
                
                if matches:
                    linkages.append({
                        "document_1": doc1_id,
                        "document_2": doc2_id,
                        "matches": matches,
                        "match_count": len(matches),
                        "linkage_strength": self._calculate_linkage_strength(matches)
                    })
        
        return linkages
    
    def _compare_fingerprints(self, fp1: Dict, fp2: Dict) -> List[Dict]:
        """Compare fingerprints between two documents"""
        matches = []
        
        # Check all entity types
        all_types = set(fp1.keys()) | set(fp2.keys())
        
        for entity_type in all_types:
            entities1 = fp1.get(entity_type, [])
            entities2 = fp2.get(entity_type, [])
            
            for e1 in entities1:
                for e2 in entities2:
                    # Check for exact or fuzzy match
                    if e1["hash"] == e2["hash"]:
                        matches.append({
                            "entity_type": entity_type,
                            "match_type": "EXACT",
                            "preview_1": e1["original"][:5] + "***",
                            "preview_2": e2["original"][:5] + "***",
                            "strength": 1.0 if entity_type in self.strong_linkage_types else 0.5
                        })
                    elif self._fuzzy_match(e1["normalized"], e2["normalized"], entity_type):
                        matches.append({
                            "entity_type": entity_type,
                            "match_type": "FUZZY",
                            "preview_1": e1["original"][:5] + "***",
                            "preview_2": e2["original"][:5] + "***",
                            "strength": 0.7 if entity_type in self.strong_linkage_types else 0.3
                        })
        
        return matches
    
    def _fuzzy_match(self, text1: str, text2: str, entity_type: str) -> bool:
        """Check for fuzzy match between normalized texts"""
        if not text1 or not text2:
            return False
        
        # Simple similarity check
        if entity_type == "PERSON_NAME":
            # Check if names share significant tokens
            tokens1 = set(text1.split())
            tokens2 = set(text2.split())
            overlap = len(tokens1 & tokens2)
            return overlap >= 1 and overlap / max(len(tokens1), len(tokens2)) > 0.5
        
        # For other types, require higher similarity
        shorter = min(len(text1), len(text2))
        if shorter < 4:
            return text1 == text2
        
        # Check prefix match (80% of shorter string)
        prefix_len = int(shorter * 0.8)
        return text1[:prefix_len] == text2[:prefix_len]
    
    def _calculate_linkage_strength(self, matches: List[Dict]) -> float:
        """Calculate overall linkage strength from matches"""
        if not matches:
            return 0.0
        
        # Strong linkage from unique identifiers
        has_strong = any(
            m["entity_type"] in self.strong_linkage_types
            for m in matches
        )
        
        if has_strong:
            return 1.0
        
        # Aggregate weak linkages
        total_strength = sum(m["strength"] for m in matches)
        
        # Multiple weak linkages increase strength
        if len(matches) >= 3:
            return min(total_strength * 1.5, 1.0)
        elif len(matches) >= 2:
            return min(total_strength * 1.2, 0.9)
        else:
            return min(total_strength, 0.6)
    
    def _calculate_combined_risk(self, linkages: List[Dict], documents: List[Dict]) -> Dict:
        """Calculate combined re-identification risk"""
        if not linkages:
            return {
                "score": 0,
                "level": "NONE",
                "explanation": "No linkages detected between documents"
            }
        
        # Find strongest linkage
        max_strength = max(l["linkage_strength"] for l in linkages)
        
        # Count total unique entity matches
        total_matches = sum(l["match_count"] for l in linkages)
        
        # Calculate risk score
        risk_score = min(max_strength * 100 + total_matches * 5, 100)
        
        # Determine risk level
        if risk_score >= 80:
            level = "CRITICAL"
            explanation = "Documents contain unique identifiers that definitively link to same individual(s)"
        elif risk_score >= 60:
            level = "HIGH"
            explanation = "Strong linkage indicators present - likely same individual(s)"
        elif risk_score >= 40:
            level = "MEDIUM"
            explanation = "Moderate linkage - combination may narrow identification"
        else:
            level = "LOW"
            explanation = "Weak linkage - some shared attributes but low re-identification risk"
        
        return {
            "score": round(risk_score, 1),
            "level": level,
            "max_linkage_strength": max_strength,
            "total_matches": total_matches,
            "explanation": explanation
        }
    
    def _build_linkage_graph(self, linkages: List[Dict]) -> Dict:
        """Build a graph representation of document linkages"""
        nodes = set()
        edges = []
        
        for linkage in linkages:
            doc1 = linkage["document_1"]
            doc2 = linkage["document_2"]
            nodes.add(doc1)
            nodes.add(doc2)
            
            edges.append({
                "source": doc1,
                "target": doc2,
                "weight": linkage["linkage_strength"],
                "matches": linkage["match_count"]
            })
        
        return {
            "nodes": list(nodes),
            "edges": edges
        }
    
    def _find_individual_clusters(self, graph: Dict) -> List[Dict]:
        """Find clusters of documents likely about the same individual"""
        if not graph["nodes"]:
            return []
        
        # Simple connected components using union-find
        parent = {node: node for node in graph["nodes"]}
        
        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        
        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py
        
        # Only union if strong linkage
        for edge in graph["edges"]:
            if edge["weight"] >= 0.7:
                union(edge["source"], edge["target"])
        
        # Group by cluster
        clusters = defaultdict(list)
        for node in graph["nodes"]:
            clusters[find(node)].append(node)
        
        return [
            {
                "cluster_id": i,
                "documents": docs,
                "document_count": len(docs),
                "interpretation": "Likely same individual" if len(docs) > 1 else "Single document"
            }
            for i, docs in enumerate(clusters.values())
            if len(docs) > 1
        ]
    
    def _generate_recommendations(self, linkages: List[Dict], risk: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if risk["level"] == "CRITICAL":
            recommendations.append(
                "CRITICAL: Do not share these documents together - they can identify specific individual(s)"
            )
            recommendations.append(
                "Remove or replace unique identifiers before sharing both documents"
            )
        
        if risk["level"] in ["CRITICAL", "HIGH"]:
            # Find which entity types cause linkage
            linking_types = set()
            for linkage in linkages:
                for match in linkage.get("matches", []):
                    linking_types.add(match["entity_type"])
            
            if linking_types:
                recommendations.append(
                    f"Entity types causing linkage: {', '.join(linking_types)}. "
                    "Consider additional redaction of these types."
                )
        
        if risk["level"] == "MEDIUM":
            recommendations.append(
                "Consider generalizing quasi-identifiers (dates, locations) to reduce linkage"
            )
        
        if len(linkages) > 0:
            recommendations.append(
                "For external sharing, consider: (1) Sharing documents separately, "
                "(2) Using synthetic replacement, or (3) Adding noise to quasi-identifiers"
            )
        
        if not recommendations:
            recommendations.append("No immediate action required - linkage risk is low")
        
        return recommendations
    
    def _generate_summary(self, linkages: List[Dict], risk: Dict) -> str:
        """Generate human-readable summary"""
        if not linkages:
            return "No cross-document linkages detected. Documents can be shared together safely."
        
        doc_pairs = len(linkages)
        total_matches = sum(l["match_count"] for l in linkages)
        
        return (
            f"Found {doc_pairs} document pair(s) with {total_matches} matching entities. "
            f"Combined risk: {risk['level']} ({risk['score']}%). "
            f"{risk['explanation']}"
        )
