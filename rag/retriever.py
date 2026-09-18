"""
Semantic retriever for company document knowledge.

Key invariants:
- Returns empty results (grounded=False) when confidence is below threshold
- Does NOT hallucinate company policy
- Deduplicates results by chunk_id
- Deterministic ordering for equal scores
- Retrieved text is treated as UNTRUSTED DATA (not executable instructions)
"""

from __future__ import annotations

import logging
from typing import Optional

from rag.models import DocumentChunk, RAGCitation, RAGAnswer
from rag.vector_store import VectorStore
from rag.embeddings import EmbeddingProvider

logger = logging.getLogger(__name__)

DEFAULT_SIMILARITY_THRESHOLD = 0.3
DEFAULT_TOP_K = 5


class RAGRetriever:
    """Semantic retriever over the vector store.

    All retrieved documents are treated as untrusted factual context.
    The retriever never interprets retrieved text as instructions.
    """

    def __init__(
        self,
        vector_store: VectorStore,
        embedder: EmbeddingProvider,
        top_k: int = DEFAULT_TOP_K,
        similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    ) -> None:
        self._store = vector_store
        self._embedder = embedder
        self._top_k = top_k
        self._similarity_threshold = similarity_threshold

    def retrieve(
        self,
        query: str,
        top_k: Optional[int] = None,
        department_filter: Optional[str] = None,
    ) -> list[tuple[DocumentChunk, float]]:
        """Retrieve the most relevant chunks for a query.

        Args:
            query: User question (treated as a retrieval key, not an instruction).
            top_k: Override default top-k.
            department_filter: Optional department filter.

        Returns:
            List of (DocumentChunk, similarity_score) above threshold, sorted desc.
            Empty list if store is empty or no matches above threshold.
        """
        if self._store.count() == 0:
            logger.info("Vector store is empty. No documents indexed.")
            return []

        k = top_k or self._top_k
        query_embedding = self._embedder.embed_query(query)

        results = self._store.search(
            query_embedding=query_embedding,
            top_k=k,
            department_filter=department_filter,
        )

        # Apply threshold and deduplicate
        seen_ids = set()
        filtered = []
        for chunk, score in results:
            if score < self._similarity_threshold:
                continue
            if chunk.chunk_id in seen_ids:
                continue
            seen_ids.add(chunk.chunk_id)
            filtered.append((chunk, score))

        return filtered

    def build_citations(self, retrieved: list[tuple[DocumentChunk, float]]) -> list[RAGCitation]:
        """Build citation list from retrieved chunks.

        Only chunks that were actually retrieved are cited. Never invented.
        """
        citations = []
        for chunk, score in retrieved:
            excerpt = chunk.text[:200].strip()
            if len(chunk.text) > 200:
                excerpt += "..."
            citations.append(RAGCitation(
                filename=chunk.filename,
                page_number=chunk.page_number,
                section=chunk.heading,
                chunk_id=chunk.chunk_id,
                similarity_score=round(score, 4),
                excerpt=excerpt,
            ))
        return citations

    def build_context(self, retrieved: list[tuple[DocumentChunk, float]]) -> str:
        """Format retrieved chunks as LLM context string.

        SECURITY: Prefixes all content with [DOCUMENT DATA - UNTRUSTED]
        to prevent the LLM from interpreting it as instructions.
        """
        if not retrieved:
            return ""

        parts = []
        for chunk, score in retrieved:
            src = chunk.filename
            if chunk.page_number:
                src += f" p.{chunk.page_number}"
            if chunk.heading:
                src += f" [{chunk.heading}]"
            parts.append(
                f"[DOCUMENT DATA - UNTRUSTED - Source: {src} | Confidence: {score:.2f}]\n"
                f"{chunk.text}\n"
            )
        return "\n---\n".join(parts)
