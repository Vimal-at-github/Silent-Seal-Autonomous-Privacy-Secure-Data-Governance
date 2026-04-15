"""
SilentSeal - Document Extractor
Handles text extraction from PDFs and images
"""

import fitz  # PyMuPDF
import pytesseract
from PIL import Image
import os
from typing import Dict, List, Any
import hashlib


class DocumentExtractor:
    """Extracts text and coordinates from PDFs and images"""
    
    def __init__(self):
        # Configure Tesseract path for Windows if needed
        # pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
        pass
    
    def extract(self, file_path: str) -> Dict[str, Any]:
        """
        Extract text and coordinates from a document
        
        Args:
            file_path: Path to the document (PDF or image)
            
        Returns:
            Dictionary with text, coordinates, and metadata
        """
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Calculate document hash for audit
        doc_hash = self._calculate_hash(file_path)
        
        if file_ext == '.pdf':
            return self._extract_pdf(file_path, doc_hash)
        elif file_ext in ['.png', '.jpg', '.jpeg', '.tiff', '.bmp']:
            return self._extract_image(file_path, doc_hash)
        else:
            raise ValueError(f"Unsupported file type: {file_ext}")
    
    def _extract_pdf(self, file_path: str, doc_hash: str) -> Dict[str, Any]:
        """Extract text from PDF with coordinates"""
        doc = fitz.open(file_path)
        
        full_text = ""
        coordinates = []
        page_count = len(doc)
        
        for page_num, page in enumerate(doc):
            # Get text blocks with coordinates
            blocks = page.get_text("dict")["blocks"]
            
            for block in blocks:
                if "lines" in block:
                    for line in block["lines"]:
                        for span in line["spans"]:
                            text = span["text"]
                            bbox = span["bbox"]  # (x0, y0, x1, y1)
                            
                            if text.strip():
                                coordinates.append({
                                    "text": text,
                                    "page": page_num,
                                    "bbox": {
                                        "x0": bbox[0],
                                        "y0": bbox[1],
                                        "x1": bbox[2],
                                        "y1": bbox[3]
                                    },
                                    "font_size": span.get("size", 12),
                                    "font_name": span.get("font", "")
                                })
                                full_text += text + " "
            
            full_text += "\n"
        
        doc.close()
        
        return {
            "text": full_text.strip(),
            "coordinates": coordinates,
            "page_count": page_count,
            "doc_hash": doc_hash,
            "source_type": "pdf"
        }
    
    def _extract_image(self, file_path: str, doc_hash: str) -> Dict[str, Any]:
        """Extract text from image using OCR"""
        # Preprocess image
        image = Image.open(file_path)
        
        # Convert to grayscale for better OCR
        if image.mode != 'L':
            image = image.convert('L')
        
        # Get OCR data with bounding boxes
        ocr_data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        
        full_text = ""
        coordinates = []
        
        n_boxes = len(ocr_data['text'])
        for i in range(n_boxes):
            text = ocr_data['text'][i]
            conf = int(ocr_data['conf'][i])
            
            # Only include text with reasonable confidence
            if conf > 30 and text.strip():
                coordinates.append({
                    "text": text,
                    "page": 0,
                    "bbox": {
                        "x0": ocr_data['left'][i],
                        "y0": ocr_data['top'][i],
                        "x1": ocr_data['left'][i] + ocr_data['width'][i],
                        "y1": ocr_data['top'][i] + ocr_data['height'][i]
                    },
                    "confidence": conf
                })
                full_text += text + " "
        
        return {
            "text": full_text.strip(),
            "coordinates": coordinates,
            "page_count": 1,
            "doc_hash": doc_hash,
            "source_type": "image"
        }
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of document for audit trail"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
