"""
intelligence/rag_knowledge.py - RAG with LOCAL embeddings

FIX: DeepSeek has NO embeddings API. Using HuggingFaceEmbeddings (free, offline).
FIX: Lazy-load embeddings (avoid blocking at import).
"""

from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

from core.config import CONFIG

console = Console()


class RAGKnowledge:
    """
    RAG vector store with local embeddings.

    Uses sentence-transformers (all-MiniLM-L6-v2) — no API key needed.
    Persists to workspace/rag_db/.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        # Singleton pattern
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, collection_name: str = "pentest_knowledge"):
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self.persist_dir = CONFIG["rag_db_dir"]
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        console.print("[cyan][*] Loading local embedding model (all-MiniLM-L6-v2)...[/cyan]")

        # FIX: local embeddings — DeepSeek has no embeddings API
        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={"device": "cpu"},
            encode_kwargs={"normalize_embeddings": True},
        )

        self.vectorstore = Chroma(
            collection_name=collection_name,
            embedding_function=self.embeddings,
            persist_directory=str(self.persist_dir),
        )

        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            separators=["\n\n", "\n", ". ", " ", ""],
        )

        console.print("[green][+] RAG initialized[/green]")

    # ─── Ingestion ────────────────────────────────────────

    def ingest_text(
        self,
        text: str,
        source: str,
        metadata: Optional[Dict] = None,
    ) -> int:
        """Split text into chunks and store."""
        if not text or not text.strip():
            return 0

        chunks = self.splitter.split_text(text)
        docs = [
            Document(
                page_content=c,
                metadata={"source": source, **(metadata or {})},
            )
            for c in chunks
        ]

        if docs:
            try:
                self.vectorstore.add_documents(docs)
            except Exception as e:
                console.print(f"[red]Ingest failed: {e}[/red]")
                return 0

        return len(docs)

    def ingest_file(self, path: Path, source: Optional[str] = None) -> int:
        """Ingest a file."""
        path = Path(path)
        if not path.exists() or not path.is_file():
            return 0
        try:
            text = path.read_text(errors="ignore")
            return self.ingest_text(text, source or str(path))
        except Exception as e:
            console.print(f"[yellow]File ingest error: {e}[/yellow]")
            return 0

    def ingest_directory(
        self,
        directory: Path,
        extensions: List[str] = None,
    ) -> int:
        """Ingest all files in a directory."""
        extensions = extensions or [".md", ".txt", ".py", ".html"]
        total = 0
        directory = Path(directory)
        if not directory.exists():
            return 0

        for f in directory.rglob("*"):
            if f.is_file() and f.suffix in extensions:
                total += self.ingest_file(f, str(f))
        return total

    def ingest_cve(self, cve_data: List[Dict]) -> int:
        """Ingest CVE records."""
        docs = []
        for cve in cve_data:
            text = (
                f"CVE ID: {cve.get('id', '')}\n"
                f"Description: {cve.get('description', '')}\n"
                f"Severity: {cve.get('severity', '')}\n"
                f"CVSS Score: {cve.get('cvss_score', '')}\n"
                f"References: {', '.join(cve.get('references', [])[:3])}\n"
            )
            docs.append(Document(
                page_content=text,
                metadata={
                    "source": "nvd",
                    "cve_id": cve.get("id", ""),
                    "severity": cve.get("severity", ""),
                },
            ))

        if docs:
            try:
                self.vectorstore.add_documents(docs)
            except Exception:
                return 0
        return len(docs)

    # ─── Retrieval ────────────────────────────────────────

    def search(self, query: str, k: int = 5) -> List[Document]:
        """Similarity search."""
        if not query or not query.strip():
            return []
        try:
            return self.vectorstore.similarity_search(query, k=k)
        except Exception as e:
            console.print(f"[red]RAG search error: {e}[/red]")
            return []

    def search_with_score(self, query: str, k: int = 5):
        """Search with relevance scores."""
        try:
            return self.vectorstore.similarity_search_with_score(query, k=k)
        except Exception:
            return []

    def build_context(self, query: str, k: int = 5) -> str:
        """Format docs into LLM prompt context."""
        docs = self.search(query, k=k)
        if not docs:
            return ""
        return "\n\n---\n\n".join(
            f"[Source: {d.metadata.get('source', 'unknown')}]\n{d.page_content}"
            for d in docs
        )

    def count(self) -> int:
        """Total docs in vectorstore."""
        try:
            return self.vectorstore._collection.count()
        except Exception:
            return 0

    def reset(self):
        """Delete all docs (careful!)."""
        try:
            self.vectorstore._client.delete_collection("pentest_knowledge")
            console.print("[yellow][!] RAG reset — restart to rebuild[/yellow]")
        except Exception as e:
            console.print(f"[red]Reset failed: {e}[/red]")


# ─── Singleton accessor ───────────────────────────────────

def get_rag() -> RAGKnowledge:
    return RAGKnowledge()


if __name__ == "__main__":
    rag = get_rag()
    console.print(f"Docs in store: {rag.count()}")
