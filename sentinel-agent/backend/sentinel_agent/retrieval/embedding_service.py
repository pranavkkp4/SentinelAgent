"""Embedding service for SentinelAgent retrieval subsystem."""

import hashlib
import numpy as np
from typing import List, Optional

from ..config import config


class EmbeddingService:
    """
    Service for generating text embeddings.
    
    Supports multiple backends:
    - sentence-transformers (preferred)
    - Fallback: simple TF-IDF-like embeddings
    """
    
    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or config.retrieval.embedding_model
        self.model = None
        self.dimension = 384  # Default for all-MiniLM-L6-v2
        self._load_model()
    
    def _load_model(self):
        """Load the embedding model."""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name, local_files_only=True)
            self.dimension = self.model.get_sentence_embedding_dimension()
            print(f"Loaded embedding model: {self.model_name}")
        except Exception as e:
            print(f"Warning: Could not load sentence-transformers: {e}")
            print("Using fallback embedding method")
            self.model = None
    
    def embed(self, text: str) -> List[float]:
        """
        Generate embedding for a single text.
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding vector
        """
        if not text:
            return [0.0] * self.dimension
        
        if self.model is not None:
            try:
                embedding = self.model.encode(text, convert_to_numpy=True)
                return embedding.tolist()
            except Exception as e:
                print(f"Error generating embedding: {e}")
        
        # Fallback: simple hash-based embedding
        return self._fallback_embed(text)
    
    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """
        Generate embeddings for multiple texts.
        
        Args:
            texts: List of texts to embed
            batch_size: Batch size for processing
            
        Returns:
            List of embedding vectors
        """
        if not texts:
            return []
        
        if self.model is not None:
            try:
                embeddings = self.model.encode(
                    texts,
                    batch_size=batch_size,
                    convert_to_numpy=True,
                    show_progress_bar=False
                )
                return [emb.tolist() for emb in embeddings]
            except Exception as e:
                print(f"Error generating batch embeddings: {e}")
        
        # Fallback
        return [self._fallback_embed(text) for text in texts]
    
    def _fallback_embed(self, text: str) -> List[float]:
        """
        Fallback embedding using deterministic hashed lexical features.

        This is not as good as learned embeddings but provides
        a working fallback when sentence-transformers is not available.
        """
        # Mix token features with character n-grams so offline retrieval remains
        # stable and reasonably specific across Python processes.
        n_grams = [2, 3, 4]
        vector = np.zeros(self.dimension)

        text_lower = text.lower()
        tokens = text_lower.split()

        for token in tokens:
            idx = self._stable_hash_index(f"tok:{token}")
            vector[idx] += 2.0

        for window in (2, 3):
            for i in range(len(tokens) - window + 1):
                phrase = " ".join(tokens[i:i + window])
                idx = self._stable_hash_index(f"phrase:{phrase}")
                vector[idx] += 1.5

        for n in n_grams:
            for i in range(len(text_lower) - n + 1):
                ngram = text_lower[i:i + n]
                idx = self._stable_hash_index(f"char:{ngram}")
                vector[idx] += 1.0

        # Normalize
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm

        return vector.tolist()

    def _stable_hash_index(self, value: str) -> int:
        """Map text to a deterministic embedding bucket."""
        digest = hashlib.sha256(value.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") % self.dimension
    
    def compute_similarity(self, embedding1: List[float],
                          embedding2: List[float]) -> float:
        """
        Compute cosine similarity between two embeddings.
        
        Args:
            embedding1: First embedding
            embedding2: Second embedding
            
        Returns:
            Cosine similarity (-1 to 1)
        """
        v1 = np.array(embedding1)
        v2 = np.array(embedding2)
        
        norm1 = np.linalg.norm(v1)
        norm2 = np.linalg.norm(v2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return float(np.dot(v1, v2) / (norm1 * norm2))
    
    def get_dimension(self) -> int:
        """Get embedding dimension."""
        return self.dimension
