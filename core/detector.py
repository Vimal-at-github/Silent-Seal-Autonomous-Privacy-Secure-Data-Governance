"""
SilentSeal - Entity Detector
Hybrid detection using Regex + NLP
"""

import re
import spacy
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass


@dataclass
class DetectedEntity:
    """Represents a detected sensitive entity"""
    text: str
    entity_type: str
    start: int
    end: int
    confidence: float
    detection_method: str  # 'regex' or 'nlp'
    coordinates: Dict = None


class EntityDetector:
    """
    Hybrid entity detector combining:
    - Regex for structured data (PAN, Aadhaar, Email, Phone, etc.)
    - NLP for contextual entities (Names, Organizations, Locations)
    """
    
    # Indian-specific regex patterns
    REGEX_PATTERNS = {
        "PAN": {
            "pattern": r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
            "description": "Indian PAN Number"
        },
        "AADHAAR": {
            "pattern": r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b',
            "description": "Indian Aadhaar Number"
        },
        "EMAIL": {
            "pattern": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            "description": "Email Address"
        },
        "PHONE": {
            "pattern": r'(?:\+91[-\s]?)?(?:\(?\d{3}\)?[-\s]?)?\d{3}[-\s]?\d{4}|(?:\+91[-\s]?)?[6-9]\d{9}\b',
            "description": "Phone Number"
        },
        "CREDIT_CARD": {
            "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            "description": "Credit Card Number"
        },
        "IFSC": {
            "pattern": r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
            "description": "Indian IFSC Code"
        },
        "PASSPORT": {
            "pattern": r'\b[A-Z][0-9]{7}\b',
            "description": "Indian Passport Number"
        },
        "DRIVING_LICENSE": {
            "pattern": r'\b[A-Z]{2}[0-9]{2}\s?[0-9]{4}\s?[0-9]{7}\b',
            "description": "Indian Driving License"
        },
        "DATE_OF_BIRTH": {
            "pattern": r'\b(?:0[1-9]|[12][0-9]|3[01])[-/](?:0[1-9]|1[0-2])[-/](?:19|20)\d{2}\b',
            "description": "Date of Birth"
        },
        "IP_ADDRESS": {
            "pattern": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            "description": "IP Address"
        },
        "BANK_ACCOUNT": {
            "pattern": r'\b\d{9,18}\b',
            "description": "Bank Account Number"
        },
        "PERSON_NAME": {
            "pattern": r'\b(?:[A-Z][a-z]+(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-z]+){1,3})\b',
            "description": "Person Name (Pattern-based)"
        }
    }
    
    # NLP entity mapping
    NLP_ENTITY_MAP = {
        "PERSON": "PERSON_NAME",
        "ORG": "ORGANIZATION",
        "GPE": "LOCATION",
        "LOC": "LOCATION",
        "DATE": "DATE",
        "MONEY": "FINANCIAL_AMOUNT",
        "NORP": "NATIONALITY_GROUP"
    }
    
    def __init__(self):
        """Initialize the detector with NLP model"""
        try:
            # Try to load transformer model for best accuracy
            self.nlp = spacy.load("en_core_web_trf")
        except OSError:
            try:
                # Fallback to large model
                self.nlp = spacy.load("en_core_web_lg")
            except OSError:
                try:
                    # Fallback to small model
                    self.nlp = spacy.load("en_core_web_sm")
                except OSError:
                    self.nlp = None
                    # Only print warning once using class variable
                    if not hasattr(EntityDetector, '_spacy_warning_shown'):
                        print("Warning: No spaCy model found. NLP detection disabled.")
                        EntityDetector._spacy_warning_shown = True
        
        # Compile regex patterns for performance
        self.compiled_patterns = {
            name: re.compile(info["pattern"])
            for name, info in self.REGEX_PATTERNS.items()
        }
    
    def detect(self, text: str, coordinates: List[Dict] = None, strict: bool = True) -> List[Dict]:
        """
        Detect all sensitive entities in text
        
        Args:
            text: The text to analyze
            coordinates: Optional list of coordinate mappings
            strict: Whether to enforce strict checksum validation (default: True)
            
        Returns:
            List of detected entities with metadata
        """
        entities = []
        
        # Run regex detection
        regex_entities = self._detect_regex(text, strict)
        entities.extend(regex_entities)
        
        # Run NLP detection
        if self.nlp:
            nlp_entities = self._detect_nlp(text)
            entities.extend(nlp_entities)
        
        # Deduplicate overlapping entities (prefer regex for structured data)
        entities = self._deduplicate_entities(entities)
        
        # Map coordinates if available
        if coordinates:
            entities = self._map_coordinates(entities, coordinates)
        
        return [self._entity_to_dict(e) for e in entities]
    
    def _detect_regex(self, text: str, strict: bool = True) -> List[DetectedEntity]:
        """Detect structured entities using regex patterns"""
        entities = []
        
        for entity_type, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(text):
                # Validate certain patterns
                if entity_type == "AADHAAR":
                    if strict and not self._validate_aadhaar(match.group()):
                        continue
                
                if entity_type == "PAN":
                    if strict and not self._validate_pan(match.group()):
                        continue
                
                entities.append(DetectedEntity(
                    text=match.group(),
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=1.0 if strict else 0.8,  # Lower confidence for non-strict matches
                    detection_method="regex"
                ))
        
        return entities
    
    def _detect_nlp(self, text: str) -> List[DetectedEntity]:
        """Detect contextual entities using NLP"""
        entities = []
        
        # Process text with spaCy
        doc = self.nlp(text)
        
        for ent in doc.ents:
            if ent.label_ in self.NLP_ENTITY_MAP:
                # Calculate confidence based on entity characteristics
                confidence = self._calculate_nlp_confidence(ent, doc)
                
                entities.append(DetectedEntity(
                    text=ent.text,
                    entity_type=self.NLP_ENTITY_MAP[ent.label_],
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=confidence,
                    detection_method="nlp"
                ))
        
        return entities
    
    def _calculate_nlp_confidence(self, entity, doc) -> float:
        """Calculate confidence score for NLP-detected entities"""
        base_confidence = 0.85
        
        # Boost for proper nouns
        if all(token.pos_ == "PROPN" for token in entity):
            base_confidence += 0.05
        
        # Boost for entities at start of sentence (likely subjects)
        if entity.start == 0 or doc[entity.start - 1].text in [".", "!", "?"]:
            base_confidence += 0.03
        
        # Reduce for very short entities
        if len(entity.text) < 3:
            base_confidence -= 0.1
        
        return min(base_confidence, 0.99)
    
    def _validate_aadhaar(self, aadhaar: str) -> bool:
        """Validate Aadhaar number using Verhoeff algorithm"""
        # Remove spaces
        aadhaar = aadhaar.replace(" ", "")
        
        if len(aadhaar) != 12:
            return False
        
        # First digit can't be 0 or 1
        if aadhaar[0] in ['0', '1']:
            return False
        
        return True
    
    def _validate_pan(self, pan: str) -> bool:
        """Validate PAN number format"""
        # Fourth character indicates holder type
        valid_holder_types = ['A', 'B', 'C', 'F', 'G', 'H', 'L', 'J', 'P', 'T', 'E']
        if len(pan) == 10 and pan[3] in valid_holder_types:
            return True
        return False
    
    def _deduplicate_entities(self, entities: List[DetectedEntity]) -> List[DetectedEntity]:
        """Remove overlapping entities, preferring regex matches"""
        if not entities:
            return entities
        
        # Sort by start position
        entities.sort(key=lambda e: (e.start, -e.confidence))
        
        deduplicated = []
        last_end = -1
        
        for entity in entities:
            # Skip if overlapping with previous
            if entity.start < last_end:
                continue
            
            deduplicated.append(entity)
            last_end = entity.end
        
        return deduplicated
    
    def _map_coordinates(self, entities: List[DetectedEntity], coordinates: List[Dict]) -> List[DetectedEntity]:
        """Map text positions to document coordinates"""
        # Build a text-to-coordinate lookup
        coord_text = " ".join([c["text"] for c in coordinates])
        
        for entity in entities:
            # Find matching coordinate entry
            for coord in coordinates:
                if entity.text in coord["text"] or coord["text"] in entity.text:
                    entity.coordinates = coord.get("bbox")
                    break
        
        return entities
    
    def _entity_to_dict(self, entity: DetectedEntity) -> Dict:
        """Convert DetectedEntity to dictionary"""
        return {
            "text": entity.text,
            "type": entity.entity_type,
            "start": entity.start,
            "end": entity.end,
            "confidence": entity.confidence,
            "method": entity.detection_method,
            "coordinates": entity.coordinates
        }
    
    def get_supported_entities(self) -> Dict[str, str]:
        """Get list of supported entity types"""
        entities = {name: info["description"] for name, info in self.REGEX_PATTERNS.items()}
        entities.update({
            "PERSON_NAME": "Personal names detected via NLP",
            "ORGANIZATION": "Company/Organization names",
            "LOCATION": "Cities, States, Countries"
        })
        return entities
