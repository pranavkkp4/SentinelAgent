"""Vector Store implementation using FAISS for SentinelAgent."""

import os
import pickle
import numpy as np
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass

from ..models import Document
from ..config import config


try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    print("Warning: FAISS not available, using fallback implementation")


@dataclass
class SearchResult:
    """Result from vector search."""
    document: Document
    score: float
    rank: int


class VectorStore:
    """
    FAISS-based vector store for document retrieval.
    
    Features:
    - Efficient similarity search
    - Persistent storage
    - Metadata tracking
    - Chunk management
    """
    
    def __init__(self, store_path: Optional[str] = None):
        self.store_path = store_path or config.retrieval.vector_store_path
        self.dimension = 384  # Default for all-MiniLM-L6-v2
        self.index = None
        self.documents: Dict[str, Document] = {}
        self.id_to_index: Dict[str, int] = {}
        self.index_to_id: Dict[int, str] = {}
        
        os.makedirs(self.store_path, exist_ok=True)
        self._init_index()
    
    def _init_index(self):
        """Initialize FAISS index."""
        if FAISS_AVAILABLE:
            # Use L2 distance index (can be switched to IP for cosine similarity)
            self.index = faiss.IndexFlatL2(self.dimension)
        else:
            # Fallback: simple numpy-based storage
            self.index = None
            self.vectors: List[np.ndarray] = []
    
    def _normalize_vector(self, vector: np.ndarray) -> np.ndarray:
        """Normalize vector for cosine similarity."""
        norm = np.linalg.norm(vector)
        if norm > 0:
            return vector / norm
        return vector
    
    def add_document(self, document: Document, embedding: List[float]) -> bool:
        """
        Add a document to the vector store.
        
        Args:
            document: Document to add
            embedding: Document embedding vector
            
        Returns:
            True if successful
        """
        try:
            vector = np.array(embedding, dtype=np.float32).reshape(1, -1)
            vector = self._normalize_vector(vector)
            
            if FAISS_AVAILABLE and self.index is not None:
                # Add to FAISS index
                index_id = self.index.ntotal
                self.index.add(vector)
            else:
                # Fallback: store in list
                index_id = len(self.vectors)
                self.vectors.append(vector)
            
            # Store document and mappings
            document.embedding = embedding
            self.documents[document.id] = document
            self.id_to_index[document.id] = index_id
            self.index_to_id[index_id] = document.id
            
            return True
            
        except Exception as e:
            print(f"Error adding document: {e}")
            return False
    
    def add_documents(self, documents: List[Document], embeddings: List[List[float]]) -> int:
        """
        Add multiple documents to the vector store.
        
        Args:
            documents: List of documents
            embeddings: List of embeddings
            
        Returns:
            Number of documents added
        """
        added = 0
        for doc, emb in zip(documents, embeddings):
            if self.add_document(doc, emb):
                added += 1
        return added
    
    def search(self, query_embedding: List[float], top_k: int = 5,
               threshold: Optional[float] = None) -> List[SearchResult]:
        """
        Search for similar documents.
        
        Args:
            query_embedding: Query embedding vector
            top_k: Number of results to return
            threshold: Minimum similarity threshold
            
        Returns:
            List of search results
        """
        if not self.documents:
            return []
        
        threshold = threshold or config.retrieval.similarity_threshold
        query_vector = np.array(query_embedding, dtype=np.float32).reshape(1, -1)
        query_vector = self._normalize_vector(query_vector)
        
        if FAISS_AVAILABLE and self.index is not None:
            # Search FAISS index
            distances, indices = self.index.search(query_vector, min(top_k * 4, self.index.ntotal))
            
            results = []
            for rank, (dist, idx) in enumerate(zip(distances[0], indices[0])):
                if idx == -1:
                    continue
                    
                doc_id = self.index_to_id.get(int(idx))
                if doc_id and doc_id in self.documents:
                    # On normalized vectors, squared L2 distance maps to cosine
                    # similarity via cos(theta) = 1 - dist / 2.
                    similarity = max(0.0, 1.0 - (float(dist) / 2.0))
                    
                    if similarity >= threshold:
                        results.append(SearchResult(
                            document=self.documents[doc_id],
                            score=float(similarity),
                            rank=rank + 1
                        ))
            
            return results[:top_k]
        else:
            # Fallback: brute force search
            return self._brute_force_search(query_vector[0], top_k, threshold)
    
    def _brute_force_search(self, query_vector: np.ndarray, top_k: int,
                           threshold: float) -> List[SearchResult]:
        """Brute force similarity search (fallback)."""
        scores = []
        
        for idx, vector in enumerate(self.vectors):
            # Cosine similarity
            similarity = np.dot(query_vector, vector[0]) / (
                np.linalg.norm(query_vector) * np.linalg.norm(vector[0]) + 1e-8
            )
            scores.append((idx, similarity))
        
        # Sort by score descending
        scores.sort(key=lambda x: x[1], reverse=True)
        
        results = []
        for rank, (idx, score) in enumerate(scores[:top_k]):
            if score >= threshold:
                doc_id = self.index_to_id.get(idx)
                if doc_id and doc_id in self.documents:
                    results.append(SearchResult(
                        document=self.documents[doc_id],
                        score=float(score),
                        rank=rank + 1
                    ))
        
        return results
    
    def get_document(self, doc_id: str) -> Optional[Document]:
        """Get document by ID."""
        return self.documents.get(doc_id)
    
    def delete_document(self, doc_id: str) -> bool:
        """
        Delete a document from the store.
        
        Note: FAISS doesn't support deletion, so we mark as deleted.
        """
        if doc_id in self.documents:
            # Mark as deleted (soft delete)
            self.documents[doc_id].metadata["deleted"] = True
            return True
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        active_docs = sum(
            1 for d in self.documents.values()
            if not d.metadata.get("deleted", False)
        )
        
        return {
            "total_documents": len(self.documents),
            "active_documents": active_docs,
            "deleted_documents": len(self.documents) - active_docs,
            "store_path": self.store_path,
            "dimension": self.dimension
        }
    
    def save(self, filename: str = "vector_store.pkl") -> bool:
        """Save vector store to disk."""
        try:
            filepath = os.path.join(self.store_path, filename)
            data = {
                "documents": self.documents,
                "id_to_index": self.id_to_index,
                "index_to_id": self.index_to_id,
                "vectors": getattr(self, 'vectors', [])
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(data, f)
            
            return True
        except Exception as e:
            print(f"Error saving vector store: {e}")
            return False
    
    def load(self, filename: str = "vector_store.pkl") -> bool:
        """Load vector store from disk."""
        try:
            filepath = os.path.join(self.store_path, filename)
            
            if not os.path.exists(filepath):
                return False
            
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
            
            self.documents = data.get("documents", {})
            self.id_to_index = data.get("id_to_index", {})
            self.index_to_id = data.get("index_to_id", {})
            
            # Rebuild index
            self._init_index()
            vectors = data.get("vectors", [])
            
            if vectors and FAISS_AVAILABLE:
                all_vectors = np.vstack(vectors)
                self.index.add(all_vectors)
            elif vectors:
                self.vectors = vectors
            
            return True
        except Exception as e:
            print(f"Error loading vector store: {e}")
            return False
    
    def clear(self):
        """Clear all documents from the store."""
        self.documents = {}
        self.id_to_index = {}
        self.index_to_id = {}
        self._init_index()
