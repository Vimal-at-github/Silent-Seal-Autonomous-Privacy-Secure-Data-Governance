"""
SilentSeal - Handwritten Document Processor
Novel feature: Advanced OCR for handwritten documents and signatures
"""

from typing import Dict, List, Any, Optional, Tuple
import os


class HandwritingProcessor:
    """
    Processes handwritten documents and detects signatures
    
    This is a NOVEL FEATURE that handles:
    - Handwritten text recognition (Indian languages)
    - Signature detection and masking
    - Mixed typed/handwritten document processing
    - Low-confidence region flagging
    """
    
    def __init__(self):
        self.easyocr_reader = None
        self.signature_detector = None
        self._init_ocr()
    
    def _init_ocr(self):
        """Initialize EasyOCR with Indian language support"""
        try:
            import easyocr
            # Support English and Hindi
            self.easyocr_reader = easyocr.Reader(['en', 'hi'], gpu=False)
        except ImportError:
            print("Warning: EasyOCR not available. Install with: pip install easyocr")
            self.easyocr_reader = None
        except Exception as e:
            print(f"Warning: EasyOCR initialization failed: {e}")
            self.easyocr_reader = None
    
    def process(self, image_path: str) -> Dict[str, Any]:
        """
        Process a handwritten document image
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Extracted text with coordinates and confidence
        """
        if not self.easyocr_reader:
            # Fallback to basic Tesseract
            return self._fallback_tesseract(image_path)
        
        # Preprocess image
        preprocessed = self._preprocess_image(image_path)
        
        # Run EasyOCR
        results = self.easyocr_reader.readtext(preprocessed or image_path)
        
        # Process results
        full_text = ""
        coordinates = []
        low_confidence_regions = []
        
        for (bbox, text, confidence) in results:
            # Convert bbox to standard format
            x0 = min(p[0] for p in bbox)
            y0 = min(p[1] for p in bbox)
            x1 = max(p[0] for p in bbox)
            y1 = max(p[1] for p in bbox)
            
            coord_entry = {
                "text": text,
                "page": 0,
                "bbox": {
                    "x0": float(x0),
                    "y0": float(y0),
                    "x1": float(x1),
                    "y1": float(y1)
                },
                "confidence": float(confidence),
                "is_handwritten": self._is_handwritten(confidence, bbox)
            }
            
            coordinates.append(coord_entry)
            full_text += text + " "
            
            # Flag low confidence regions for manual review
            if confidence < 0.5:
                low_confidence_regions.append({
                    "bbox": coord_entry["bbox"],
                    "text": text,
                    "confidence": confidence,
                    "reason": "Low OCR confidence - may need manual review"
                })
        
        # Detect signatures
        signature_regions = self._detect_signatures(image_path, coordinates)
        
        return {
            "text": full_text.strip(),
            "coordinates": coordinates,
            "page_count": 1,
            "doc_hash": self._calculate_hash(image_path),
            "source_type": "handwritten_image",
            "handwriting_detected": any(c.get("is_handwritten") for c in coordinates),
            "low_confidence_regions": low_confidence_regions,
            "signature_regions": signature_regions,
            "needs_review": len(low_confidence_regions) > 0 or len(signature_regions) > 0
        }
    
    def _preprocess_image(self, image_path: str) -> Optional[str]:
        """Preprocess image for better OCR results"""
        try:
            from PIL import Image, ImageFilter, ImageOps
            import tempfile
            
            img = Image.open(image_path)
            
            # Convert to grayscale
            if img.mode != 'L':
                img = img.convert('L')
            
            # Increase contrast
            img = ImageOps.autocontrast(img)
            
            # Apply slight sharpening
            img = img.filter(ImageFilter.SHARPEN)
            
            # Denoise
            img = img.filter(ImageFilter.MedianFilter(size=3))
            
            # Save preprocessed image
            temp_path = tempfile.mktemp(suffix='.png')
            img.save(temp_path)
            
            return temp_path
            
        except Exception as e:
            print(f"Warning: Image preprocessing failed: {e}")
            return None
    
    def _is_handwritten(self, confidence: float, bbox: List) -> bool:
        """
        Heuristic to detect if text region is handwritten
        
        Based on:
        - OCR confidence (handwriting typically lower)
        - Bounding box aspect ratio (handwriting often irregular)
        """
        # Lower confidence often indicates handwriting
        if confidence < 0.7:
            return True
        
        # Check aspect ratio irregularity
        x_coords = [p[0] for p in bbox]
        y_coords = [p[1] for p in bbox]
        width = max(x_coords) - min(x_coords)
        height = max(y_coords) - min(y_coords)
        
        if height > 0:
            aspect = width / height
            # Very irregular aspect ratios suggest handwriting
            if aspect > 15 or aspect < 0.5:
                return True
        
        return False
    
    def _detect_signatures(self, image_path: str, text_regions: List[Dict]) -> List[Dict]:
        """
        Detect signature regions in the image
        
        Uses heuristics:
        - Regions with very low text confidence
        - Regions near signature keywords
        - Regions with unusual stroke patterns
        """
        signature_regions = []
        
        # Look for signature-related keywords
        signature_keywords = ["signature", "sign", "signed", "authorized", "approved", 
                            "witness", "signatory", "हस्ताक्षर"]
        
        for i, region in enumerate(text_regions):
            text_lower = region["text"].lower()
            
            # Check if near signature keyword
            is_near_signature = any(kw in text_lower for kw in signature_keywords)
            
            # Check for very low confidence with specific patterns
            if region["confidence"] < 0.3 and region.get("is_handwritten"):
                signature_regions.append({
                    "bbox": region["bbox"],
                    "confidence": region["confidence"],
                    "type": "DETECTED_SIGNATURE",
                    "reason": "Low confidence handwritten region"
                })
            
            elif is_near_signature:
                # Look for region immediately below signature keyword
                if i + 1 < len(text_regions):
                    next_region = text_regions[i + 1]
                    if next_region["confidence"] < 0.5:
                        signature_regions.append({
                            "bbox": next_region["bbox"],
                            "confidence": next_region["confidence"],
                            "type": "PROBABLE_SIGNATURE",
                            "reason": f"Region following '{region['text']}'"
                        })
        
        return signature_regions
    
    def _fallback_tesseract(self, image_path: str) -> Dict[str, Any]:
        """Fallback to Tesseract if EasyOCR not available"""
        try:
            import pytesseract
            from PIL import Image
            
            img = Image.open(image_path)
            
            # Get OCR data with confidence
            ocr_data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
            
            full_text = ""
            coordinates = []
            
            n_boxes = len(ocr_data['text'])
            for i in range(n_boxes):
                text = ocr_data['text'][i]
                conf = int(ocr_data['conf'][i])
                
                if conf > 0 and text.strip():
                    coordinates.append({
                        "text": text,
                        "page": 0,
                        "bbox": {
                            "x0": ocr_data['left'][i],
                            "y0": ocr_data['top'][i],
                            "x1": ocr_data['left'][i] + ocr_data['width'][i],
                            "y1": ocr_data['top'][i] + ocr_data['height'][i]
                        },
                        "confidence": conf / 100.0,
                        "is_handwritten": conf < 60
                    })
                    full_text += text + " "
            
            return {
                "text": full_text.strip(),
                "coordinates": coordinates,
                "page_count": 1,
                "doc_hash": self._calculate_hash(image_path),
                "source_type": "image_tesseract",
                "handwriting_detected": any(c.get("is_handwritten") for c in coordinates),
                "low_confidence_regions": [
                    c for c in coordinates if c["confidence"] < 0.5
                ],
                "signature_regions": [],
                "needs_review": False
            }
            
        except Exception as e:
            return {
                "text": "",
                "coordinates": [],
                "page_count": 1,
                "doc_hash": "",
                "source_type": "error",
                "error": str(e)
            }
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate file hash for audit trail"""
        import hashlib
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def get_review_report(self, processing_result: Dict) -> Dict[str, Any]:
        """
        Generate a human-review report for uncertain regions
        
        Returns regions that need manual verification
        """
        report = {
            "needs_review": processing_result.get("needs_review", False),
            "total_regions": len(processing_result.get("coordinates", [])),
            "low_confidence_count": len(processing_result.get("low_confidence_regions", [])),
            "signature_count": len(processing_result.get("signature_regions", [])),
            "review_items": []
        }
        
        # Add low confidence regions
        for region in processing_result.get("low_confidence_regions", []):
            report["review_items"].append({
                "type": "LOW_CONFIDENCE",
                "bbox": region["bbox"],
                "detected_text": region["text"],
                "confidence": region["confidence"],
                "action_required": "Verify text content is correctly extracted"
            })
        
        # Add signature regions
        for region in processing_result.get("signature_regions", []):
            report["review_items"].append({
                "type": "SIGNATURE",
                "bbox": region["bbox"],
                "confidence": region.get("confidence", 0),
                "action_required": "Verify signature detection and redaction"
            })
        
        return report
