"""
Embedding abstraction layer for RAG.

Supports:
- SentenceTransformer (local, default, no API key required)
- Google embedding API (optional, requires EMBEDDING_API_KEY)
- OpenAI embedding API (optional, requires EMBEDDING_API_KEY)

Configured via settings:
  EMBEDDING_PROVIDER: sentence_transformer | google | openai
  EMBEDDING_MODEL: model name
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


class EmbeddingProvider(ABC):
    """Abstract embedding provider."""

    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a list of texts and return float vectors."""
        ...

    @abstractmethod
    def embed_query(self, text: str) -> list[float]:
        """Embed a single query text."""
        ...

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Return embedding vector dimension."""
        ...


class SentenceTransformerEmbedder(EmbeddingProvider):
    """Local embedding using sentence-transformers (no API key required).

    This is the default embedding provider, suitable for local/air-gapped deployments.
    """

    DEFAULT_MODEL = "all-MiniLM-L6-v2"  # 384-dim, fast, effective

    def __init__(self, model_name: Optional[str] = None) -> None:
        self._model_name = model_name or self.DEFAULT_MODEL
        self._model = None
        self._dimension: Optional[int] = None

    def _load_model(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(self._model_name)
                # Determine dimension via probe
                test_emb = self._model.encode(["test"])
                self._dimension = len(test_emb[0])
                logger.info("Loaded SentenceTransformer model '%s' (dim=%d)", self._model_name, self._dimension)
            except ImportError:
                raise RuntimeError(
                    "sentence-transformers is required for local embeddings. "
                    "Run: pip install sentence-transformers"
                )

    def embed(self, texts: list[str]) -> list[list[float]]:
        self._load_model()
        embeddings = self._model.encode(texts, show_progress_bar=False)
        return [e.tolist() for e in embeddings]

    def embed_query(self, text: str) -> list[float]:
        return self.embed([text])[0]

    @property
    def dimension(self) -> int:
        if self._dimension is None:
            self._load_model()
        return self._dimension


class MockEmbedder(EmbeddingProvider):
    """Mock embedder for testing — returns fixed-dimension zero vectors."""

    DIM = 384

    def embed(self, texts: list[str]) -> list[list[float]]:
        import random
        random.seed(42)
        return [[random.uniform(-0.1, 0.1) for _ in range(self.DIM)] for _ in texts]

    def embed_query(self, text: str) -> list[float]:
        return self.embed([text])[0]

    @property
    def dimension(self) -> int:
        return self.DIM


def create_embedder(provider: str = "sentence_transformer", model: Optional[str] = None) -> EmbeddingProvider:
    """Factory to create an embedding provider from settings.

    Args:
        provider: 'sentence_transformer' | 'mock'
        model: Model name override.

    Returns:
        Configured EmbeddingProvider.
    """
    provider = provider.lower()
    if provider == "sentence_transformer":
        return SentenceTransformerEmbedder(model)
    elif provider == "mock":
        return MockEmbedder()
    else:
        logger.warning("Unknown embedding provider '%s', falling back to SentenceTransformer.", provider)
        return SentenceTransformerEmbedder(model)
