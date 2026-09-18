"""
RAG data models.

All structured data flowing through the RAG pipeline is defined here as
Pydantic models, ensuring type safety and clear contracts.

Critical: These models represent KNOWLEDGE only, never execution authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from pydantic import BaseModel, Field


class DocumentChunk(BaseModel):
    """A single text chunk from an ingested document with full provenance metadata."""
    chunk_id: str = Field(..., description="Unique chunk ID: '{filename}:p{page}:c{idx:03d}'")
    doc_id: str = Field(..., description="Parent document SHA-256 hash")
    filename: str = Field(..., description="Source filename")
    source_path: str = Field("", description="Absolute source file path")
    page_number: Optional[int] = Field(None, description="Page number if available (1-indexed)")
    heading: Optional[str] = Field(None, description="Nearest section heading above this chunk")
    text: str = Field(..., description="Chunk text content")
    chunk_index: int = Field(0, description="Chunk index within document")
    document_type: str = Field("unknown", description="Document type: pdf, docx, txt, md")
    department: Optional[str] = Field(None, description="Department/category if supplied")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IngestedDocument(BaseModel):
    """Metadata record for a successfully ingested document."""
    doc_id: str = Field(..., description="SHA-256 hash of document content")
    filename: str = Field(..., description="Source filename")
    source_path: str = Field(..., description="Absolute file path")
    document_hash: str = Field(..., description="SHA-256 content hash")
    chunk_count: int = Field(0, description="Number of indexed chunks")
    document_type: str = Field("unknown", description="Document type")
    department: Optional[str] = Field(None, description="Department/category")
    indexed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RAGCitation(BaseModel):
    """A verifiable citation for a statement in a RAG answer.

    Only generated from actually retrieved chunks. Never invented.
    """
    filename: str = Field(..., description="Source document filename")
    page_number: Optional[int] = Field(None, description="Page number if available")
    section: Optional[str] = Field(None, description="Section heading if available")
    chunk_id: str = Field(..., description="Chunk ID for traceability")
    similarity_score: float = Field(0.0, description="Retrieval similarity score (0-1)")
    excerpt: str = Field("", description="Short excerpt from the retrieved chunk")
    department: Optional[str] = Field(None, description="Source document department")

    @property
    def source(self) -> str:
        """Alias for filename for backwards compatibility."""
        return self.filename

    def format_citation(self) -> str:
        """Format citation for user display."""
        parts = [f"Source: {self.filename}"]
        if self.department:
            parts.append(f"Dept: {self.department}")
        if self.page_number:
            parts.append(f"Page: {self.page_number}")
        if self.section:
            parts.append(f"Section: {self.section}")
        return ", ".join(parts)


class RAGAnswer(BaseModel):
    """Structured grounded answer from the RAG system.

    Invariant: grounded=True ONLY if retrieved_chunks is non-empty.
    If grounded=False, no citations should be present.
    This model is KNOWLEDGE ONLY — it has no authority over AWS execution.
    """
    answer: str = Field(..., description="Answer text grounded in company documents")
    grounded: bool = Field(False, description="Whether answer is grounded in retrieved documents")
    citations: list[RAGCitation] = Field(default_factory=list, description="Source citations")
    retrieved_chunks: list[DocumentChunk] = Field(default_factory=list, description="Raw retrieved chunks")
    confidence: float = Field(0.0, description="Retrieval confidence score (0-1)")
    query: str = Field("", description="Original query")
    low_confidence_message: Optional[str] = Field(
        None,
        description="Message shown when confidence is too low to ground the answer"
    )

    @property
    def has_sources(self) -> bool:
        return len(self.citations) > 0

    def format_answer_with_citations(self) -> str:
        """Format answer with inline citation block."""
        if not self.grounded or not self.citations:
            return self.answer
        lines = [self.answer, "", "**Sources:**"]
        for i, c in enumerate(self.citations, 1):
            lines.append(f"{i}. {c.format_citation()}")
        return "\n".join(lines)
