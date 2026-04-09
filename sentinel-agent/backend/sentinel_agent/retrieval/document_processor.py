"""Document processing for SentinelAgent retrieval subsystem."""

import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from ..models import Document
from ..config import config


@dataclass
class TextChunk:
    """Represents a chunk of text."""
    content: str
    start_index: int
    end_index: int
    metadata: Dict[str, Any]


class DocumentProcessor:
    """
    Processes documents for retrieval.
    
    Features:
    - Text chunking with overlap
    - Metadata extraction
    - Content cleaning
    """
    
    def __init__(self):
        self.chunk_size = config.retrieval.chunk_size
        self.chunk_overlap = config.retrieval.chunk_overlap
    
    def chunk_text(self, text: str, source: str = "",
                   metadata: Optional[Dict] = None) -> List[TextChunk]:
        """
        Split text into overlapping chunks.
        
        Args:
            text: Text to chunk
            source: Source identifier
            metadata: Additional metadata
            
        Returns:
            List of text chunks
        """
        if not text:
            return []
        
        chunks = []
        start = 0
        chunk_index = 0
        
        while start < len(text):
            end = start + self.chunk_size
            
            # Try to break at sentence boundary
            if end < len(text):
                # Look for sentence ending
                search_end = min(end + 100, len(text))
                sentence_end = self._find_sentence_boundary(text, end, search_end)
                if sentence_end > 0:
                    end = sentence_end
            
            chunk_content = text[start:end].strip()
            
            if chunk_content:
                chunk_metadata = {
                    "source": source,
                    "chunk_index": chunk_index,
                    "start_index": start,
                    "end_index": end,
                    **(metadata or {})
                }
                
                chunks.append(TextChunk(
                    content=chunk_content,
                    start_index=start,
                    end_index=end,
                    metadata=chunk_metadata
                ))
                
                chunk_index += 1
            
            # Move start with overlap
            start = end - self.chunk_overlap
            if start >= end:
                start = end
        
        return chunks
    
    def _find_sentence_boundary(self, text: str, start: int, end: int) -> int:
        """Find a good sentence boundary within range."""
        # Look for period, question mark, or exclamation followed by space
        for i in range(start, min(end, len(text))):
            if text[i] in '.!?' and i + 1 < len(text) and text[i + 1].isspace():
                return i + 1
        return -1
    
    def clean_text(self, text: str) -> str:
        """Clean and normalize text."""
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)

        # Remove control characters
        text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]', '', text)

        # Normalize common smart quotes/dashes to ASCII for consistent indexing.
        replacements = {
            "\u2018": "'",
            "\u2019": "'",
            "\u201c": '"',
            "\u201d": '"',
            "\u2013": "-",
            "\u2014": "-",
        }
        for original, normalized in replacements.items():
            text = text.replace(original, normalized)

        return text.strip()
    
    def extract_metadata(self, text: str, source: str) -> Dict[str, Any]:
        """Extract metadata from text."""
        return {
            "source": source,
            "word_count": len(text.split()),
            "char_count": len(text),
            "line_count": text.count('\n') + 1
        }
    
    def process_document(self, content: str, source: str = "",
                        metadata: Optional[Dict] = None) -> List[Document]:
        """
        Process a document into chunks ready for indexing.
        
        Args:
            content: Document content
            source: Document source
            metadata: Additional metadata
            
        Returns:
            List of Document chunks
        """
        # Clean text
        cleaned = self.clean_text(content)
        
        # Extract metadata
        doc_metadata = self.extract_metadata(cleaned, source)
        doc_metadata.update(metadata or {})
        
        # Chunk text
        chunks = self.chunk_text(cleaned, source, doc_metadata)
        
        # Convert to Documents
        documents = []
        for chunk in chunks:
            doc = Document(
                content=chunk.content,
                metadata=chunk.metadata,
                source=source,
                chunk_index=chunk.metadata["chunk_index"]
            )
            documents.append(doc)
        
        return documents
    
    def process_documents(self, documents: List[Dict[str, Any]]) -> List[Document]:
        """
        Process multiple documents.
        
        Args:
            documents: List of dicts with 'content', 'source', 'metadata'
            
        Returns:
            List of Document chunks
        """
        all_chunks = []
        
        for doc in documents:
            chunks = self.process_document(
                content=doc.get("content", ""),
                source=doc.get("source", ""),
                metadata=doc.get("metadata", {})
            )
            all_chunks.extend(chunks)
        
        return all_chunks
