"""
SilentSeal - Document Redactor
Performs irreversible scrubbing of sensitive data from PDFs
"""

import fitz  # PyMuPDF
from PIL import Image, ImageDraw
import io
import os
from typing import List, Dict, Any


class DocumentRedactor:
    """
    Performs irreversible redaction on documents
    - Removes text from PDF text stream (not just visual overlay)
    - Modifies XREF tables to eliminate copy-paste vulnerability
    - Supports both masking and synthetic replacement
    """
    
    def __init__(self):
        self.redaction_color = (0, 0, 0)  # Black
        self.replacement_color = (0.2, 0.2, 0.2)  # Dark gray for replacements
    
    def redact(self, input_path: str, output_path: str, redaction_map: List[Dict]) -> Dict[str, Any]:
        """
        Perform irreversible redaction on a document
        
        Args:
            input_path: Path to original document
            output_path: Path to save redacted document
            redaction_map: List of entities to redact with optional replacements
            
        Returns:
            Dictionary with redaction statistics
        """
        file_ext = os.path.splitext(input_path)[1].lower()
        
        if file_ext == '.pdf':
            return self._redact_pdf(input_path, output_path, redaction_map)
        elif file_ext in ['.png', '.jpg', '.jpeg', '.tiff', '.bmp']:
            return self._redact_image(input_path, output_path, redaction_map)
        else:
            raise ValueError(f"Unsupported file type: {file_ext}")
    
    def _redact_pdf(self, input_path: str, output_path: str, redaction_map: List[Dict]) -> Dict[str, Any]:
        """Perform irreversible PDF redaction"""
        doc = fitz.open(input_path)
        
        redaction_count = 0
        pages_affected = set()
        
        for item in redaction_map:
            entity = item.get("entity", {})
            replacement = item.get("replacement")
            
            text_to_find = entity.get("text", "")
            if not text_to_find:
                continue
            
            # Search for text across all pages
            for page_num, page in enumerate(doc):
                # Find all instances of the text
                text_instances = page.search_for(text_to_find)
                
                for rect in text_instances:
                    # Method 1: Add redaction annotation (marks for permanent removal)
                    if replacement:
                        # Replace with synthetic data
                        annot = page.add_redact_annot(rect, text=replacement)
                        annot.set_colors(stroke=self.replacement_color, fill=self.replacement_color)
                    else:
                        # Complete blackout
                        annot = page.add_redact_annot(rect)
                        annot.set_colors(stroke=self.redaction_color, fill=self.redaction_color)
                    
                    redaction_count += 1
                    pages_affected.add(page_num)
        
        # Apply all redactions (this permanently removes the text)
        for page in doc:
            page.apply_redactions()
        
        # Additional scrubbing: Remove metadata that might contain sensitive info
        doc.set_metadata({})
        
        # Clean the document to remove any remnant data
        doc.scrub()
        
        # Save with garbage collection to remove unused objects
        doc.save(output_path, garbage=4, deflate=True, clean=True)
        doc.close()
        
        return {
            "redactions_applied": redaction_count,
            "pages_affected": len(pages_affected),
            "output_path": output_path,
            "scrubbed": True
        }
    
    def _redact_image(self, input_path: str, output_path: str, redaction_map: List[Dict]) -> Dict[str, Any]:
        """Perform redaction on images"""
        image = Image.open(input_path)
        draw = ImageDraw.Draw(image)
        
        redaction_count = 0
        
        for item in redaction_map:
            entity = item.get("entity", {})
            coordinates = entity.get("coordinates")
            
            if coordinates:
                # Draw black rectangle over sensitive area
                bbox = (
                    coordinates["x0"],
                    coordinates["y0"],
                    coordinates["x1"],
                    coordinates["y1"]
                )
                draw.rectangle(bbox, fill="black")
                redaction_count += 1
        
        # Save as PDF for consistency
        if output_path.endswith('.pdf'):
            # Convert image to PDF
            pdf_bytes = io.BytesIO()
            image.save(pdf_bytes, format='PDF')
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes.getvalue())
        else:
            image.save(output_path)
        
        return {
            "redactions_applied": redaction_count,
            "pages_affected": 1,
            "output_path": output_path,
            "scrubbed": True
        }
    
    def verify_redaction(self, file_path: str, original_entities: List[Dict]) -> Dict[str, Any]:
        """
        Verify that redaction was successful by checking if entities are still extractable
        
        Args:
            file_path: Path to redacted document
            original_entities: List of entities that should have been redacted
            
        Returns:
            Verification report
        """
        doc = fitz.open(file_path)
        
        leaked_entities = []
        
        for entity in original_entities:
            text_to_check = entity.get("text", "")
            for page in doc:
                # Check if text can still be found
                if page.search_for(text_to_check):
                    leaked_entities.append(entity)
                    break
                
                # Also check raw text stream
                if text_to_check in page.get_text():
                    leaked_entities.append(entity)
                    break
        
        doc.close()
        
        return {
            "verified": len(leaked_entities) == 0,
            "total_entities": len(original_entities),
            "leaked_entities": len(leaked_entities),
            "leaked_details": leaked_entities
        }
    
    def create_comparison_view(self, original_path: str, redacted_path: str, output_path: str):
        """
        Create a side-by-side comparison view of original and redacted documents
        Useful for audit and verification purposes
        """
        original = fitz.open(original_path)
        redacted = fitz.open(redacted_path)
        
        comparison = fitz.open()
        
        for i in range(min(len(original), len(redacted))):
            # Create new page with double width
            orig_page = original[i]
            rect = orig_page.rect
            
            new_page = comparison.new_page(width=rect.width * 2 + 20, height=rect.height)
            
            # Insert original on left
            new_page.show_pdf_page(fitz.Rect(0, 0, rect.width, rect.height), original, i)
            
            # Insert redacted on right  
            new_page.show_pdf_page(fitz.Rect(rect.width + 20, 0, rect.width * 2 + 20, rect.height), redacted, i)
            
            # Add labels
            new_page.insert_text((10, 20), "ORIGINAL", fontsize=14, color=(1, 0, 0))
            new_page.insert_text((rect.width + 30, 20), "REDACTED", fontsize=14, color=(0, 0.5, 0))
        
        comparison.save(output_path)
        
        original.close()
        redacted.close()
        comparison.close()
