"""
Cryptographic Audit Logger (SHA-256 Hash Chained Logs).
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

class AuditLogger:
    """Append-only, tamper-evident audit logger with SHA-256 chain of custody hashes."""

    def __init__(self, log_file_path: str = "audit_logs/agentshield_audit.jsonl"):
        self.log_file_path = Path(log_file_path)
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()
        self._cached_integrity_result: Optional[Dict[str, Any]] = None
        self._cached_file_stat: Optional[tuple] = None

    def _read_last_hash(self) -> str:
        if not self.log_file_path.exists():
            return "0000000000000000000000000000000000000000000000000000000000000000"
        try:
            with open(self.log_file_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if lines:
                    last_entry = json.loads(lines[-1])
                    return last_entry.get("hash", "0000000000000000000000000000000000000000000000000000000000000000")
        except Exception:
            pass
        return "0000000000000000000000000000000000000000000000000000000000000000"

    def log_event(self, event_type: str, details: Dict[str, Any], tenant_id: str = "default") -> Dict[str, Any]:
        """Logs a security or execution event with hash signature chaining."""
        timestamp = time.time()
        payload = {
            "timestamp": timestamp,
            "event_type": event_type,
            "tenant_id": tenant_id,
            "details": details,
            "prev_hash": self._last_hash
        }

        # Calculate current entry hash
        raw = json.dumps(payload, sort_keys=True)
        current_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        payload["hash"] = current_hash
        self._last_hash = current_hash

        # Append to log file
        with open(self.log_file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")

        return payload

    def verify_log_integrity(self, force_reverify: bool = False) -> Dict[str, Any]:
        """Verifies hash chain integrity of the log file using state-invalidation caching."""
        if not self.log_file_path.exists():
            return {"valid": True, "entries_checked": 0}

        try:
            stat_info = self.log_file_path.stat()
            current_stat = (stat_info.st_mtime_ns, stat_info.st_size)
        except OSError:
            current_stat = None

        if not force_reverify and self._cached_integrity_result is not None and current_stat is not None and self._cached_file_stat == current_stat:
            return self._cached_integrity_result

        prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        count = 0

        with open(self.log_file_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                count += 1
                entry = json.loads(line)
                stored_hash = entry.get("hash")
                
                # Copy entry without hash to re-compute
                check_payload = {
                    "timestamp": entry["timestamp"],
                    "event_type": entry["event_type"],
                    "tenant_id": entry["tenant_id"],
                    "details": entry["details"],
                    "prev_hash": entry["prev_hash"]
                }
                computed_hash = hashlib.sha256(json.dumps(check_payload, sort_keys=True).encode("utf-8")).hexdigest()
                
                if computed_hash != stored_hash or entry["prev_hash"] != prev_hash:
                    res = {"valid": False, "broken_at_entry": count, "expected": computed_hash, "found": stored_hash}
                    self._cached_integrity_result = res
                    self._cached_file_stat = current_stat
                    return res
                
                prev_hash = stored_hash

        res = {"valid": True, "entries_checked": count}
        self._cached_integrity_result = res
        self._cached_file_stat = current_stat
        return res

