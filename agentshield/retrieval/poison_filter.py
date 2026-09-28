"""
Poison Document Filter for RAG inputs.
"""

from typing import Dict, Any, List
from agentshield.security.injection import PromptInjectionScanner

class PoisonDocumentFilter:
    """Scans retrieved documents / vector snippets for hidden prompt injection payloads."""

    def __init__(self, threshold: float = 0.70):
        self.injection_scanner = PromptInjectionScanner(threshold=threshold)

    def scan_document(self, doc_content: str, doc_id: str = "unknown") -> Dict[str, Any]:
        """Scans a single retrieved document for malicious payloads."""
        res = self.injection_scanner.scan(doc_content)
        return {
            "doc_id": doc_id,
            "is_poisoned": res["is_injection"],
            "score": res["max_score"],
            "matches": res["matches"]
        }

    def filter_documents(self, documents: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Filters out poisoned documents from a list of retrieved document dicts."""
        safe_docs = []
        for doc in documents:
            content = doc.get("content", "")
            doc_id = doc.get("id", "doc")
            res = self.scan_document(content, doc_id)
            if not res["is_poisoned"]:
                safe_docs.append(doc)
        return safe_docs
