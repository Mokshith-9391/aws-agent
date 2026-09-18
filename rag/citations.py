"""
Citation extraction and formatting for RAG answers.

Citations are ONLY generated from actually retrieved chunks.
This module never invents citations or sources.
"""

from __future__ import annotations

from rag.models import RAGCitation, DocumentChunk


def format_citations_markdown(citations: list[RAGCitation]) -> str:
    """Format citations as a Markdown list for display."""
    if not citations:
        return ""

    lines = ["\n**Sources:**"]
    for i, c in enumerate(citations, 1):
        parts = [f"**{c.filename}**"]
        if c.page_number:
            parts.append(f"Page {c.page_number}")
        if c.section:
            parts.append(f"Section: _{c.section}_")
        if c.excerpt:
            parts.append(f'> "{c.excerpt}"')
        lines.append(f"{i}. " + " - ".join(parts))

    return "\n".join(lines)


def deduplicate_citations(citations: list[RAGCitation]) -> list[RAGCitation]:
    """Remove duplicate citations (same filename + page + section)."""
    seen = set()
    unique = []
    for c in citations:
        key = (c.filename, c.page_number, c.section)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def build_citations_from_chunks(chunks: list[tuple[DocumentChunk, float]]) -> list[RAGCitation]:
    """Build a deduplicated citation list from retrieved chunks."""
    raw = []
    for chunk, score in chunks:
        excerpt = chunk.text[:200].strip()
        if len(chunk.text) > 200:
            excerpt += "..."
        raw.append(RAGCitation(
            filename=chunk.filename,
            page_number=chunk.page_number,
            section=chunk.heading,
            chunk_id=chunk.chunk_id,
            similarity_score=round(score, 4),
            excerpt=excerpt,
            department=chunk.department,
        ))
    return deduplicate_citations(raw)
