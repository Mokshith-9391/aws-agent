"""
RAGService - unified facade for company document knowledge.

Architecture:
  Company Documents
       |
       v
  DocumentLoader (PDF/DOCX/TXT/MD)
       |
       v
  TextChunker (deterministic, overlap-aware)
       |
       v
  EmbeddingProvider (sentence-transformers / Google / OpenAI)
       |
       v
  VectorStore (ChromaDB persistent)
       |
       v
  RAGRetriever (similarity threshold, deduplication)
       |
       v
  LLM (grounded answer with citations)
       |
       v
  RAGAnswer (answer + citations + confidence)

Security invariants:
- Retrieved documents are UNTRUSTED DATA (not executable instructions)
- The RAG system CANNOT issue AWS commands, approve plans, or change targets
- The system explicitly refuses to invent citations or company policy
- Malicious document instructions are explicitly neutralized in prompts
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any, Optional

from rag.chunking import TextChunker
from rag.citations import build_citations_from_chunks, format_citations_markdown
from rag.embeddings import EmbeddingProvider, MockEmbedder, create_embedder
from rag.ingestion import DocumentLoader, DocumentLoadError
from rag.models import (
    DocumentChunk,
    IngestedDocument,
    RAGAnswer,
    RAGCitation,
)
from rag.prompts import (
    NO_KNOWLEDGE_RESPONSE,
    RAG_PLANNING_CONTEXT_TEMPLATE,
    RAG_QUERY_TEMPLATE,
    RAG_SYSTEM_PROMPT,
)
from rag.retriever import RAGRetriever
from rag.vector_store import VectorStore

logger = logging.getLogger(__name__)


class RAGService:
    """Unified facade for company document RAG.

    This service is KNOWLEDGE ONLY and has no authority over AWS execution.
    All retrieved content is treated as untrusted factual data.
    """

    def __init__(
        self,
        vector_store_path: str = "./rag_store",
        embedding_provider: str = "sentence_transformer",
        embedding_model: Optional[str] = None,
        top_k: int = 5,
        similarity_threshold: float = 0.30,
        chunk_size: int = 800,
        chunk_overlap: int = 100,
        llm_client: Optional[Any] = None,  # Optional LLM for answer generation
    ) -> None:
        self._loader = DocumentLoader()
        self._chunker = TextChunker(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        self._embedder: EmbeddingProvider = create_embedder(embedding_provider, embedding_model)
        self._store = VectorStore(persist_path=vector_store_path)
        self._retriever = RAGRetriever(
            vector_store=self._store,
            embedder=self._embedder,
            top_k=top_k,
            similarity_threshold=similarity_threshold,
        )
        self._llm = llm_client
        self._index: dict[str, IngestedDocument] = {}  # doc_hash -> IngestedDocument

    # -- Document Management -------------------------------------------------

    def ingest_document(
        self,
        file_path: str,
        department: Optional[str] = None,
        force_reindex: bool = False,
    ) -> IngestedDocument:
        """Ingest a company document into the knowledge base.

        Idempotent: if the document content has not changed (same SHA-256),
        the existing index is returned without duplicating chunks.

        Args:
            file_path: Path to document file.
            department: Optional department/category label.
            force_reindex: Force re-indexing even if hash unchanged.

        Returns:
            IngestedDocument metadata record.

        Raises:
            DocumentLoadError: If file cannot be loaded or is unsupported.
        """
        path = Path(file_path)
        doc_hash = self._loader.compute_hash(path)

        # Idempotency check: same hash means no content change
        if not force_reindex and doc_hash in self._index:
            existing = self._index[doc_hash]
            logger.info("Document '%s' already indexed (hash=%s), skipping.", path.name, doc_hash[:8])
            return existing

        # If hash changed: delete old version first
        for existing_hash, existing_doc in list(self._index.items()):
            if existing_doc.filename == path.name and existing_hash != doc_hash:
                logger.info("Document '%s' content changed. Replacing index.", path.name)
                self._store.delete_documents(existing_hash)
                del self._index[existing_hash]
                break

        # Load and chunk
        segments = self._loader.load(path)
        doc_type = path.suffix.lower().lstrip(".")
        if doc_type == "markdown":
            doc_type = "md"

        chunks = self._chunker.chunk_document(
            segments=segments,
            doc_id=doc_hash,
            filename=path.name,
            source_path=str(path.absolute()),
            document_type=doc_type,
            department=department,
        )

        if not chunks:
            raise DocumentLoadError(f"No text content extracted from '{path.name}'.")

        # Embed and store
        texts = [c.text for c in chunks]
        embeddings = self._embedder.embed(texts)
        self._store.add_documents(chunks, embeddings)

        doc_record = IngestedDocument(
            doc_id=doc_hash,
            filename=path.name,
            source_path=str(path.absolute()),
            document_hash=doc_hash,
            chunk_count=len(chunks),
            document_type=doc_type,
            department=department,
        )
        self._index[doc_hash] = doc_record
        logger.info("Ingested '%s': %d chunks, hash=%s", path.name, len(chunks), doc_hash[:8])
        return doc_record

    def delete_document(self, doc_id: str) -> int:
        """Remove a document from the knowledge base.

        Args:
            doc_id: SHA-256 document hash.

        Returns:
            Number of chunks removed.
        """
        count = self._store.delete_documents(doc_id)
        self._index.pop(doc_id, None)
        return count

    def list_documents(self) -> list[IngestedDocument]:
        """Return all indexed documents."""
        return list(self._index.values())

    def document_count(self) -> int:
        """Return number of indexed chunks."""
        return self._store.count()

    # -- Knowledge Q&A -------------------------------------------------------

    def query(self, question: str, top_k: Optional[int] = None, department: Optional[str] = None) -> RAGAnswer:
        """Answer a company knowledge question grounded in indexed documents.

        Args:
            question: User question.
            top_k: Number of chunks to retrieve.
            department: Optional department filter.

        Returns:
            RAGAnswer with grounded answer, citations, and confidence.
            If no relevant content found, returns grounded=False answer.
        """
        retrieved = self._retriever.retrieve(question, top_k=top_k, department_filter=department)

        if not retrieved:
            return RAGAnswer(
                answer=NO_KNOWLEDGE_RESPONSE,
                grounded=False,
                citations=[],
                retrieved_chunks=[],
                confidence=0.0,
                query=question,
                low_confidence_message="No relevant company documents found for this question.",
            )

        confidence = retrieved[0][1] if retrieved else 0.0
        citations = build_citations_from_chunks(retrieved)
        chunks = [c for c, _ in retrieved]
        context = self._retriever.build_context(retrieved)

        # Generate grounded answer via LLM if available
        if self._llm:
            answer = self._generate_llm_answer(question, context)
        else:
            # Fallback: excerpt-based answer
            answer = self._build_excerpt_answer(question, retrieved)

        return RAGAnswer(
            answer=answer,
            grounded=True,
            citations=citations,
            retrieved_chunks=chunks,
            confidence=round(confidence, 4),
            query=question,
        )

    def get_planning_context(self, user_request: str, top_k: Optional[int] = None) -> Optional[str]:
        """Retrieve company policy context for infrastructure planning.

        Returns context string to inject into LLM planning prompt,
        or None if no relevant documents found.

        SECURITY: This context is informational only. It CANNOT authorize
        AWS operations or change the execution target.
        """
        retrieved = self._retriever.retrieve(user_request, top_k=top_k or 3)
        if not retrieved:
            return None

        context = self._retriever.build_context(retrieved)
        return RAG_PLANNING_CONTEXT_TEMPLATE.format(context=context)

    def _generate_llm_answer(self, question: str, context: str) -> str:
        """Generate a grounded answer using the LLM.

        The LLM is constrained by RAG_SYSTEM_PROMPT to treat all retrieved
        content as untrusted data and never emit AWS commands.
        """
        try:
            prompt = RAG_QUERY_TEMPLATE.format(question=question, context=context)
            answer = self._llm.generate(
                system_prompt=RAG_SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=0.0,
                max_tokens=2048,
            )
            # Safety check: strip any CLI-like content from LLM output
            answer = self._safety_strip_cli(answer)
            return answer
        except Exception as e:
            logger.warning("LLM answer generation failed: %s. Using excerpt fallback.", e)
            return self._build_excerpt_answer(question, [])

    @staticmethod
    def _safety_strip_cli(text: str) -> str:
        """Remove or neutralize any AWS CLI command patterns that appear in the answer.

        This is a defense-in-depth measure. The system prompt should prevent
        CLI output, but this strips any that may have leaked through or originated
        from untrusted document excerpts.
        """
        import re
        lines = text.splitlines()
        safe_lines = []
        for line in lines:
            # If line starts with aws command, drop it
            if re.match(r'^\s*aws\s+\w+', line):
                continue
            # If line contains an aws cli command anywhere, neutralize the command part
            if re.search(r'aws\s+[a-z0-9-]+\s+[a-z0-9-]+', line, re.IGNORECASE):
                line = re.sub(r'aws\s+[a-z0-9-]+\s+[a-z0-9-]+[^\n]*', '[BLOCKED: Command removed by RAG safety layer]', line, flags=re.IGNORECASE)
            safe_lines.append(line)
        return "\n".join(safe_lines)

    @classmethod
    def _build_excerpt_answer(cls, question: str, retrieved: list[tuple[DocumentChunk, float]]) -> str:
        """Build a basic answer from chunk excerpts (no LLM required)."""
        if not retrieved:
            return NO_KNOWLEDGE_RESPONSE
        lines = [f"Based on company documents, here is relevant information for '{question}':", ""]
        for chunk, score in retrieved[:3]:
            src = chunk.filename
            if chunk.page_number:
                src += f" p.{chunk.page_number}"
            excerpt = chunk.text[:400].strip()
            lines.append(f"**From {src}:**")
            lines.append(f"> {excerpt}")
            lines.append("")
        raw_answer = "\n".join(lines)
        return cls._safety_strip_cli(raw_answer)
