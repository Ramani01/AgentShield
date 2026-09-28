"""
RAG Guardrail Facade.
"""

from typing import List, Dict, Any
from agentshield.retrieval.poison_filter import PoisonDocumentFilter
from agentshield.retrieval.access_control import DocumentAccessControl

class RAGGuardrail:
    """Facade combining retrieval access control and poison document filtering."""

    def __init__(self, threshold: float = 0.70):
        self.poison_filter = PoisonDocumentFilter(threshold=threshold)
        self.access_control = DocumentAccessControl()

    def process_retrieved_documents(
        self,
        documents: List[Dict[str, Any]],
        user_roles: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Applies role-based access filtering and checks for poisoned documents.
        """
        # Step 1: Filter by RBAC
        rbac_filtered = self.access_control.filter_by_role(documents, user_roles)

        # Step 2: Filter poisoned items
        clean_documents = self.poison_filter.filter_documents(rbac_filtered)

        return clean_documents
