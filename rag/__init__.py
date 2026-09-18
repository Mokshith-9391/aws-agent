"""RAG package — Company Document Retrieval-Augmented Generation.

This package provides secure, isolated document ingestion, chunking, embedding,
vector storage, and retrieval for company knowledge Q&A.

Key design invariants:
- Retrieved documents are UNTRUSTED DATA only (not executable instructions)
- The RAG system CANNOT issue AWS commands, approve plans, or change targets
- The deterministic compiler, policy engine, and approval engine remain authoritative
- Citations are only generated from actually retrieved chunks, never invented
"""

from rag.service import RAGService
from rag.models import RAGAnswer, RAGCitation, IngestedDocument, DocumentChunk

__all__ = ["RAGService", "RAGAnswer", "RAGCitation", "IngestedDocument", "DocumentChunk"]
