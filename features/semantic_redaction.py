"""
SilentSeal - Semantic Concept Redaction
Novel feature: Redact text based on conceptual meaning using vector embeddings
"""

from typing import List, Dict, Any, Tuple
import re
import numpy as np

class SemanticRedactor:
    """
    Redacts text based on semantic meaning/concepts using vector embeddings.
    
    This is a NOVEL FEATURE that allows users to redact based on natural language queries
    like "redact all medical information" or "remove negative feedback", going beyond
    simple pattern matching.
    """
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        """
        Initialize with a sentence-transformer model.
        Using a lightweight model for balance of speed and performance.
        """
        self.model = None
        self.model_name = model_name
        self._load_model()
        
    def _load_model(self):
        """Lazy load the model to save resources if feature not used"""
        try:
            from sentence_transformers import SentenceTransformer
            print(f"Loading semantic model: {self.model_name}...")
            self.model = SentenceTransformer(self.model_name)
            print("Semantic model loaded successfully.")
        except ImportError:
            print("Warning: sentence-transformers not installed. Semantic redaction disabled.")
        except Exception as e:
            print(f"Error loading semantic model: {e}")

    def redact(self, text: str, query: str, threshold: float = 0.4) -> List[Dict[str, Any]]:
        """
        Identify text segments that match the semantic query.
        
        Args:
            text: The document text
            query: The natural language concept to redact (e.g. "medical diagnosis")
            threshold: Similarity threshold (0-1), higher is stricter
            
        Returns:
            List of redaction entries with coordinates (start, end, score)
        """
        if not self.model or not query:
            return []
            
        # 1. Segment text into sentences/clauses for granular analysis
        # We split by common delimiters to get meaningful chunks
        segments = self._segment_text(text)
        if not segments:
            return []
            
        segment_texts = [s['text'] for s in segments]
        
        # 2. Encode query and segments
        # Encode query
        query_embedding = self.model.encode(query, convert_to_tensor=True)
        
        # Encode segments (batch processing)
        segment_embeddings = self.model.encode(segment_texts, convert_to_tensor=True)
        
        # 3. Compute cosine similarities
        from sentence_transformers import util
        # util.cos_sim returns a tensor matrix [1, n_segments]
        scores = util.cos_sim(query_embedding, segment_embeddings)[0]
        
        # 4. Filter by threshold and create results
        redactions = []
        
        for idx, score in enumerate(scores):
            if score > threshold:
                segment = segments[idx]
                redactions.append({
                    "text": segment['text'],
                    "start": segment['start'],
                    "end": segment['end'],
                    "type": "SEMANTIC_CONCEPT",
                    "score": float(score),
                    "query": query,
                    "reason": f"Matches concept: '{query}'"
                })
                
        return redactions

    def _segment_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Split text into analyzable segments (sentences).
        Returns list of dicts with text and char offsets.
        """
        # Simple regex-based sentence splitting for robustness
        # Looks for [.!?] followed by space or end of string
        sentence_pattern = re.compile(r'([^.!?]+[.!?]+)(\s+|$)|([^.!?]+$)')
        
        segments = []
        current_pos = 0
        
        # Iterate over matches to preserve exact offsets
        for match in sentence_pattern.finditer(text):
            span_text = match.group(0)
            start = match.start()
            end = match.end()
            
            # Clean up whitespace for embedding, but keep offsets for original text
            clean_text = span_text.strip()
            
            if len(clean_text) > 3: # Ignore tiny segments
                segments.append({
                    "text": clean_text,
                    "start": start,
                    "end": end
                })
                
        return segments
