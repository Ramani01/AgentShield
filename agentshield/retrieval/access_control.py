"""
Document Level Access Control (RBAC for RAG).
"""

from typing import List, Dict, Any, Set

class DocumentAccessControl:
    """Filters retrieved knowledge base documents based on user roles and ACL permissions."""

    def filter_by_role(self, documents: List[Dict[str, Any]], user_roles: List[str]) -> List[Dict[str, Any]]:
        """
        Filters documents requiring specific roles.
        Each doc can specify 'required_roles': ['admin', 'finance'].
        """
        user_role_set = set(user_roles)
        authorized_docs = []

        for doc in documents:
            required = doc.get("required_roles", [])
            # If doc has no explicit role requirements, it is public
            if not required:
                authorized_docs.append(doc)
                continue

            # Check role intersection
            if user_role_set.intersection(set(required)):
                authorized_docs.append(doc)

        return authorized_docs
