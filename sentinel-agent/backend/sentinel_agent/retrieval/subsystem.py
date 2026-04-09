"""Retrieval Subsystem for SentinelAgent."""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from .vector_store import VectorStore, SearchResult
from .document_processor import DocumentProcessor
from .embedding_service import EmbeddingService
from ..models import Document
from ..config import config


@dataclass
class RetrievalResult:
    """Result from document retrieval."""
    documents: List[Document]
    query: str
    total_found: int
    filtered_count: int
    search_time_ms: float


class RetrievalSubsystem:
    """
    Retrieval-Augmented Generation (RAG) subsystem.
    
    Features:
    - Document indexing and storage
    - Semantic search with embeddings
    - Chunk management
    - Security screening integration
    """
    
    def __init__(self, store_path: Optional[str] = None):
        self.vector_store = VectorStore(store_path)
        self.document_processor = DocumentProcessor()
        self.embedding_service = EmbeddingService()
        self.stats = {
            "total_indexed": 0,
            "total_searches": 0,
            "avg_search_time_ms": 0
        }
    
    def index_document(self, content: str, source: str = "",
                      metadata: Optional[Dict] = None) -> List[str]:
        """
        Index a document for retrieval.
        
        Args:
            content: Document content
            source: Document source identifier
            metadata: Additional metadata
            
        Returns:
            List of document IDs for created chunks
        """
        # Process document into chunks
        documents = self.document_processor.process_document(
            content=content,
            source=source,
            metadata=metadata
        )
        
        if not documents:
            return []
        
        # Generate embeddings
        texts = [doc.content for doc in documents]
        embeddings = self.embedding_service.embed_batch(texts)
        
        # Add to vector store
        doc_ids = []
        for doc, embedding in zip(documents, embeddings):
            if self.vector_store.add_document(doc, embedding):
                doc_ids.append(doc.id)
        
        self.stats["total_indexed"] += len(doc_ids)
        
        return doc_ids
    
    def index_documents(self, documents: List[Dict[str, Any]]) -> int:
        """
        Index multiple documents.
        
        Args:
            documents: List of document dicts
            
        Returns:
            Number of chunks indexed
        """
        total = 0
        for doc in documents:
            ids = self.index_document(
                content=doc.get("content", ""),
                source=doc.get("source", ""),
                metadata=doc.get("metadata", {})
            )
            total += len(ids)
        
        return total
    
    def retrieve(self, query: str, top_k: Optional[int] = None,
                 threshold: Optional[float] = None) -> RetrievalResult:
        """
        Retrieve relevant documents for a query.
        
        Args:
            query: Search query
            top_k: Number of results (default from config)
            threshold: Similarity threshold
            
        Returns:
            RetrievalResult with documents
        """
        import time
        
        top_k = top_k or config.retrieval.top_k
        
        start_time = time.time()
        
        # Generate query embedding
        query_embedding = self.embedding_service.embed(query)
        
        # Search vector store
        results = self.vector_store.search(
            query_embedding=query_embedding,
            top_k=top_k,
            threshold=threshold
        )
        
        search_time = (time.time() - start_time) * 1000
        
        # Update stats
        self.stats["total_searches"] += 1
        self.stats["avg_search_time_ms"] = (
            (self.stats["avg_search_time_ms"] * (self.stats["total_searches"] - 1) + search_time)
            / self.stats["total_searches"]
        )
        
        # Extract documents
        documents = [r.document for r in results]
        
        return RetrievalResult(
            documents=documents,
            query=query,
            total_found=len(results),
            filtered_count=0,
            search_time_ms=search_time
        )
    
    def retrieve_with_context(self, query: str, 
                              max_tokens: int = 2000) -> Dict[str, Any]:
        """
        Retrieve documents and format as context for LLM.
        
        Args:
            query: Search query
            max_tokens: Maximum context tokens (approximate)
            
        Returns:
            Dict with formatted context and metadata
        """
        result = self.retrieve(query)
        
        # Format context
        context_parts = []
        total_chars = 0
        max_chars = max_tokens * 4  # Rough approximation
        
        for i, doc in enumerate(result.documents, 1):
            part = f"[Document {i}] Source: {doc.source}\n{doc.content}\n\n"
            
            if total_chars + len(part) > max_chars:
                break
            
            context_parts.append(part)
            total_chars += len(part)
        
        return {
            "context": "".join(context_parts),
            "documents": result.documents,
            "query": query,
            "search_time_ms": result.search_time_ms,
            "total_found": result.total_found
        }
    
    def get_document(self, doc_id: str) -> Optional[Document]:
        """Get a document by ID."""
        return self.vector_store.get_document(doc_id)
    
    def delete_document(self, doc_id: str) -> bool:
        """Delete a document."""
        return self.vector_store.delete_document(doc_id)
    
    def save(self) -> bool:
        """Save the retrieval subsystem state."""
        return self.vector_store.save()
    
    def load(self) -> bool:
        """Load the retrieval subsystem state."""
        return self.vector_store.load()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get retrieval statistics."""
        return {
            **self.stats,
            **self.vector_store.get_stats()
        }
    
    def clear(self):
        """Clear all indexed documents."""
        self.vector_store.clear()
        self.stats = {
            "total_indexed": 0,
            "total_searches": 0,
            "avg_search_time_ms": 0
        }
