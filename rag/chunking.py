"""
Deterministic text chunker for company documents.

Preserves:
- Document structure and headings
- Page number provenance for PDFs
- Section context across chunks
- Configurable overlap between adjacent chunks

Chunk IDs are deterministic: '{filename}:p{page}:c{idx:03d}'
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from rag.models import DocumentChunk


@dataclass
class RawTextSegment:
    """A raw text segment from a document loader before chunking."""
    text: str
    page_number: Optional[int] = None
    heading: Optional[str] = None
    segment_index: int = 0


class TextChunker:
    """Deterministic text chunker with overlap and heading preservation."""

    HEADING_PATTERNS = [
        re.compile(r'^#{1,6}\s+(.+)$', re.MULTILINE),     # Markdown headings
        re.compile(r'^(.+)\n[=\-]{3,}$', re.MULTILINE),    # Underline headings
        re.compile(r'^\d+\.\s+(.+)$', re.MULTILINE),       # Numbered headings
    ]

    def __init__(
        self,
        chunk_size: int = 800,
        chunk_overlap: int = 100,
    ) -> None:
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk_document(
        self,
        segments: list[RawTextSegment],
        doc_id: str,
        filename: str,
        source_path: str,
        document_type: str,
        department: Optional[str] = None,
    ) -> list[DocumentChunk]:
        """Convert raw text segments into overlapping DocumentChunks.

        Args:
            segments: Raw text segments from document loader.
            doc_id: SHA-256 document hash.
            filename: Source filename.
            source_path: Absolute file path.
            document_type: Document type (pdf, docx, txt, md).
            department: Optional department/category.

        Returns:
            List of DocumentChunks with full provenance metadata.
        """
        chunks: list[DocumentChunk] = []
        chunk_idx = 0
        current_heading: Optional[str] = None

        for seg in segments:
            # Update heading context from segment
            detected_heading = self._extract_heading(seg.text)
            if detected_heading:
                current_heading = detected_heading
            elif seg.heading:
                current_heading = seg.heading

            text = seg.text.strip()
            if not text:
                continue

            # Split large segments into overlapping chunks
            sub_chunks = self._split_with_overlap(text)
            for sub_idx, sub_text in enumerate(sub_chunks):
                if not sub_text.strip():
                    continue

                chunk_id = self._make_chunk_id(
                    filename=filename,
                    page=seg.page_number or 0,
                    idx=chunk_idx,
                )
                chunks.append(DocumentChunk(
                    chunk_id=chunk_id,
                    doc_id=doc_id,
                    filename=filename,
                    source_path=source_path,
                    page_number=seg.page_number,
                    heading=current_heading,
                    text=sub_text.strip(),
                    chunk_index=chunk_idx,
                    document_type=document_type,
                    department=department,
                ))
                chunk_idx += 1

        return chunks

    def _split_with_overlap(self, text: str) -> list[str]:
        """Split text into overlapping chunks."""
        if len(text) <= self.chunk_size:
            return [text]

        chunks = []
        start = 0
        while start < len(text):
            end = min(start + self.chunk_size, len(text))

            # Try to split at a sentence boundary
            if end < len(text):
                for boundary in ('. ', '! ', '? ', '\n\n', '\n'):
                    idx = text.rfind(boundary, start, end)
                    if idx > start:
                        end = idx + len(boundary)
                        break

            chunk = text[start:end]
            if chunk.strip():
                chunks.append(chunk)

            # Move start forward with overlap
            next_start = max(start + 1, end - self.chunk_overlap)
            if next_start <= start:
                break
            start = next_start

        return chunks

    def _extract_heading(self, text: str) -> Optional[str]:
        """Extract the first heading found in text."""
        for pattern in self.HEADING_PATTERNS:
            m = pattern.search(text[:500])  # Only look at beginning
            if m:
                return m.group(1).strip()[:200]  # Cap heading length
        return None

    @staticmethod
    def _make_chunk_id(filename: str, page: int, idx: int) -> str:
        """Create deterministic chunk ID."""
        safe_name = filename.replace("/", "_").replace("\\", "_")
        return f"{safe_name}:p{page}:c{idx:03d}"
