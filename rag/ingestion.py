"""
Document ingestion pipeline for company documents.

Supports: PDF, DOCX, TXT, Markdown

Key properties:
- SHA-256 content hashing for idempotent re-ingestion detection
- Per-page metadata extraction for PDFs
- Heading detection for all formats
- Safe failure for corrupted/malformed documents
- Sensitive data is NEVER stored in chunk metadata
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Optional

from rag.chunking import RawTextSegment

logger = logging.getLogger(__name__)


class DocumentLoadError(Exception):
    """Raised when a document cannot be loaded or parsed."""
    pass


class DocumentLoader:
    """Loads and extracts text segments from company documents.

    All content is treated as untrusted factual data.
    This class never executes any content found in documents.
    """

    SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".md", ".markdown"}

    def compute_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of file content."""
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for block in iter(lambda: f.read(65536), b""):
                    sha.update(block)
            return sha.hexdigest()
        except OSError as e:
            raise DocumentLoadError(f"Cannot read file for hashing: {e}")

    def is_supported(self, file_path: Path) -> bool:
        """Check if file type is supported."""
        return file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def load(self, file_path: Path) -> list[RawTextSegment]:
        """Load document and return raw text segments with metadata.

        Args:
            file_path: Path to document.

        Returns:
            List of RawTextSegments with text, page number, and heading.

        Raises:
            DocumentLoadError: If file is unsupported, missing, or corrupt.
        """
        if not file_path.exists():
            raise DocumentLoadError(f"File not found: {file_path}")

        suffix = file_path.suffix.lower()
        if suffix not in self.SUPPORTED_EXTENSIONS:
            raise DocumentLoadError(
                f"Unsupported file type '{suffix}'. Supported: {sorted(self.SUPPORTED_EXTENSIONS)}"
            )

        try:
            if suffix == ".pdf":
                return self._load_pdf(file_path)
            elif suffix == ".docx":
                return self._load_docx(file_path)
            elif suffix in (".txt", ".md", ".markdown"):
                return self._load_text(file_path)
        except DocumentLoadError:
            raise
        except Exception as e:
            raise DocumentLoadError(f"Failed to load '{file_path.name}': {e}")

        return []

    def _load_pdf(self, file_path: Path) -> list[RawTextSegment]:
        """Load PDF, extracting text per page."""
        try:
            import pypdf
        except ImportError:
            raise DocumentLoadError("pypdf is required for PDF support. Run: pip install pypdf")

        segments = []
        current_heading = None
        try:
            reader = pypdf.PdfReader(str(file_path))
            if len(reader.pages) == 0:
                raise DocumentLoadError(f"PDF '{file_path.name}' has no pages.")

            for page_num, page in enumerate(reader.pages, 1):
                try:
                    text = page.extract_text() or ""
                except Exception:
                    text = ""

                if not text.strip():
                    continue

                # Detect heading in first line of page
                first_line = text.split("\n")[0].strip() if "\n" in text else ""
                if first_line and len(first_line) < 120 and not first_line.endswith("."):
                    current_heading = first_line

                segments.append(RawTextSegment(
                    text=text,
                    page_number=page_num,
                    heading=current_heading,
                    segment_index=page_num - 1,
                ))
        except DocumentLoadError:
            raise
        except Exception as e:
            raise DocumentLoadError(f"PDF parsing failed for '{file_path.name}': {e}")

        return segments

    def _load_docx(self, file_path: Path) -> list[RawTextSegment]:
        """Load DOCX, extracting paragraphs with heading detection."""
        try:
            import docx
        except ImportError:
            raise DocumentLoadError("python-docx is required for DOCX support. Run: pip install python-docx")

        segments = []
        current_heading = None
        current_text_parts = []
        segment_idx = 0

        try:
            doc = docx.Document(str(file_path))
            for para in doc.paragraphs:
                style_name = para.style.name if para.style else ""
                text = para.text.strip()
                if not text:
                    continue

                is_heading = "Heading" in style_name or "Title" in style_name
                if is_heading:
                    # Flush current buffer
                    if current_text_parts:
                        segments.append(RawTextSegment(
                            text="\n".join(current_text_parts),
                            page_number=None,
                            heading=current_heading,
                            segment_index=segment_idx,
                        ))
                        segment_idx += 1
                        current_text_parts = []
                    current_heading = text
                else:
                    current_text_parts.append(text)

            # Flush remaining
            if current_text_parts:
                segments.append(RawTextSegment(
                    text="\n".join(current_text_parts),
                    page_number=None,
                    heading=current_heading,
                    segment_index=segment_idx,
                ))
        except DocumentLoadError:
            raise
        except Exception as e:
            raise DocumentLoadError(f"DOCX parsing failed for '{file_path.name}': {e}")

        return segments

    def _load_text(self, file_path: Path) -> list[RawTextSegment]:
        """Load TXT/Markdown, splitting at headings and paragraph breaks."""
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            raise DocumentLoadError(f"Cannot read text file '{file_path.name}': {e}")

        segments = []
        current_heading = None
        current_text_parts = []
        segment_idx = 0
        heading_re = re.compile(r'^(#{1,6})\s+(.+)', re.MULTILINE)

        for line in content.splitlines():
            m = heading_re.match(line)
            if m:
                # Flush buffer
                if current_text_parts:
                    segments.append(RawTextSegment(
                        text="\n".join(current_text_parts),
                        page_number=None,
                        heading=current_heading,
                        segment_index=segment_idx,
                    ))
                    segment_idx += 1
                    current_text_parts = []
                current_heading = m.group(2).strip()
                current_text_parts.append(line)  # Include heading in chunk
            else:
                current_text_parts.append(line)

        # Flush remaining
        if current_text_parts:
            segments.append(RawTextSegment(
                text="\n".join(current_text_parts),
                page_number=None,
                heading=current_heading,
                segment_index=segment_idx,
            ))

        return segments if segments else [RawTextSegment(text=content, segment_index=0)]
