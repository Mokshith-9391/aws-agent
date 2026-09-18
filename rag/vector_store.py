"""
Persistent vector store for RAG using ChromaDB.

Provides clean interface:
  add_documents(chunks, embeddings)
  delete_documents(doc_id)
  search(query_embedding, top_k, filters)
  count()
  reset()

ChromaDB stores data on disk at VECTOR_STORE_PATH, enabling restart persistence
without external cloud infrastructure.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from rag.models import DocumentChunk

logger = logging.getLogger(__name__)

COLLECTION_NAME = "company_documents"


class VectorStore:
    """ChromaDB-backed persistent vector store with clean interface."""

    def __init__(self, persist_path: str = "./rag_store") -> None:
        self._persist_path = persist_path
        self._client = None
        self._collection = None

    def _get_collection(self):
        """Lazily initialize ChromaDB client and collection."""
        if self._collection is not None:
            return self._collection

        try:
            import chromadb
            Path(self._persist_path).mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=self._persist_path)
            self._collection = self._client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            logger.info("ChromaDB collection '%s' initialized at '%s'", COLLECTION_NAME, self._persist_path)
        except ImportError:
            raise RuntimeError("chromadb is required for vector storage. Run: pip install chromadb")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize ChromaDB: {e}")

        return self._collection

    def add_documents(self, chunks: list[DocumentChunk], embeddings: list[list[float]]) -> None:
        """Add document chunks with their embeddings to the store.

        Args:
            chunks: DocumentChunk objects to store.
            embeddings: Corresponding embedding vectors.
        """
        if not chunks:
            return
        if len(chunks) != len(embeddings):
            raise ValueError(f"Mismatch: {len(chunks)} chunks but {len(embeddings)} embeddings")

        collection = self._get_collection()
        ids = [c.chunk_id for c in chunks]
        metadatas = [
            {
                "doc_id": c.doc_id,
                "filename": c.filename,
                "source_path": c.source_path,
                "page_number": c.page_number or 0,
                "heading": c.heading or "",
                "chunk_index": c.chunk_index,
                "document_type": c.document_type,
                "department": c.department or "",
            }
            for c in chunks
        ]
        documents = [c.text for c in chunks]

        # Upsert (insert or update) to maintain idempotency
        collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas,
        )
        logger.info("Added/updated %d chunks in vector store", len(chunks))

    def delete_documents(self, doc_id: str) -> int:
        """Delete all chunks belonging to a document.

        Args:
            doc_id: SHA-256 document hash.

        Returns:
            Number of chunks deleted.
        """
        collection = self._get_collection()
        # Query to find matching IDs
        results = collection.get(where={"doc_id": doc_id})
        ids_to_delete = results.get("ids", [])
        if ids_to_delete:
            collection.delete(ids=ids_to_delete)
            logger.info("Deleted %d chunks for doc_id='%s'", len(ids_to_delete), doc_id)
        return len(ids_to_delete)

    def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        doc_id_filter: Optional[str] = None,
        department_filter: Optional[str] = None,
    ) -> list[tuple[DocumentChunk, float]]:
        """Semantic similarity search.

        Args:
            query_embedding: Query vector.
            top_k: Number of results to return.
            doc_id_filter: Optional filter to specific document.
            department_filter: Optional filter by department.

        Returns:
            List of (DocumentChunk, similarity_score) tuples, sorted by score descending.
        """
        collection = self._get_collection()
        where = None
        if doc_id_filter:
            where = {"doc_id": doc_id_filter}
        elif department_filter:
            where = {"department": department_filter}

        try:
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=min(top_k, max(1, self.count())),
                where=where,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            logger.warning("Vector store search failed: %s", e)
            return []

        chunks_with_scores = []
        for i, doc_id_ in enumerate(results["ids"][0]):
            text = results["documents"][0][i]
            meta = results["metadatas"][0][i]
            dist = results["distances"][0][i]
            # ChromaDB cosine distance -> similarity: sim = 1 - dist
            similarity = max(0.0, min(1.0, 1.0 - dist))

            chunk = DocumentChunk(
                chunk_id=doc_id_,
                doc_id=meta.get("doc_id", ""),
                filename=meta.get("filename", ""),
                source_path=meta.get("source_path", ""),
                page_number=meta.get("page_number") or None,
                heading=meta.get("heading") or None,
                text=text,
                chunk_index=meta.get("chunk_index", 0),
                document_type=meta.get("document_type", "unknown"),
                department=meta.get("department") or None,
            )
            chunks_with_scores.append((chunk, similarity))

        # Sort by similarity descending, then chunk_id for ties (deterministic)
        chunks_with_scores.sort(key=lambda x: (-x[1], x[0].chunk_id))
        return chunks_with_scores

    def count(self) -> int:
        """Return total number of chunks in the store."""
        try:
            collection = self._get_collection()
            return collection.count()
        except Exception:
            return 0

    def reset(self) -> None:
        """Delete and recreate the collection (for testing)."""
        if self._client is not None:
            try:
                self._client.delete_collection(COLLECTION_NAME)
            except Exception:
                pass
            self._collection = None
        logger.info("Vector store reset.")

    def list_doc_ids(self) -> list[str]:
        """Return list of unique document IDs in the store."""
        try:
            collection = self._get_collection()
            results = collection.get(include=["metadatas"])
            seen = set()
            doc_ids = []
            for meta in results.get("metadatas", []):
                d = meta.get("doc_id", "")
                if d and d not in seen:
                    seen.add(d)
                    doc_ids.append(d)
            return doc_ids
        except Exception:
            return []
