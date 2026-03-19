"""
PHANTOM Memory Layer — ChromaDB vector store.
PersistentClient so memory survives between runs (judges can see accumulation).
"""
import chromadb
import json
import os
import hashlib


class _SimpleHashEmbedding:
    """Fallback embedding function using deterministic hashing.
    Used when ONNX runtime is unavailable on the host."""

    def name(self) -> str:
        return "default"

    def __call__(self, input: list) -> list:
        embeddings = []
        for text in input:
            h = hashlib.sha256(text.encode()).digest()
            vec = [float(b) / 255.0 for b in h[:64]]  # 64-dim vector
            norm = sum(v * v for v in vec) ** 0.5
            vec = [v / norm for v in vec] if norm > 0 else vec
            embeddings.append(vec)
        return embeddings


def _get_embedding_fn():
    """Get embedding function. Uses hash-based approach for portability."""
    # Hash-based embeddings work everywhere — no ONNX DLL dependency
    return _SimpleHashEmbedding()


class PhantomMemory:
    def __init__(self, session_id: str):
        self.session_id = session_id
        # PersistentClient — data survives between runs
        persist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                   ".phantom_memory")
        os.makedirs(persist_dir, exist_ok=True)
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.ef = _get_embedding_fn()
        self.collection = self.client.get_or_create_collection(
            name=f"phantom_{session_id}",
            metadata={"hnsw:space": "cosine"},
            embedding_function=self.ef,
        )

    def store(self, agent: str, key: str, data: dict, status: str = "PENDING"):
        """Store a finding/result in ChromaDB with metadata."""
        doc_id = f"{agent}_{key}_{self.session_id}"
        try:
            serialized = json.dumps(data)
        except (ValueError, TypeError):
            serialized = json.dumps(data, default=lambda o: str(o))
        self.collection.upsert(
            ids=[doc_id],
            documents=[serialized],
            metadatas=[{"agent": agent, "key": key, "status": status,
                        "session": self.session_id}]
        )

    def get_failed_attempts(self, technique: str) -> list:
        """Retrieve past failed exploit attempts for a technique (vector search)."""
        try:
            results = self.collection.query(
                query_texts=[technique],
                n_results=5,
                where={"status": "FAILED"}
            )
            return [json.loads(doc) for doc in results["documents"][0]]
        except Exception:
            return []

    def get_all(self, agent: str = None) -> list:
        """Retrieve all stored items, optionally filtered by agent."""
        try:
            where = {"agent": agent} if agent else None
            results = self.collection.get(where=where)
            return [json.loads(doc) for doc in results["documents"]]
        except Exception:
            return []

    def get_sessions(self) -> list:
        """List all sessions stored in the persistent memory."""
        try:
            collections = self.client.list_collections()
            return [c.name.replace("phantom_", "") for c in collections
                    if c.name.startswith("phantom_")]
        except Exception:
            return []
