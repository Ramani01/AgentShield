"""
Unit tests for memory safety modules.
"""

import pytest
from agentshield.memory.store import SafeMemoryStore
from agentshield.memory.filter import MemoryFilter
from agentshield.memory.tamper import TamperDetector

def test_safe_memory_store_tenant_isolation():
    store = SafeMemoryStore()

    store.set(tenant_id="tenant_A", key="user_note", value="Secret A")
    assert store.get(tenant_id="tenant_A", key="user_note") == "Secret A"
    assert store.get(tenant_id="tenant_B", key="user_note") is None

def test_memory_filter():
    mem_filter = MemoryFilter()

    raw_text = "Store my email user@domain.com and key sk-12345678901234567890123456789012"
    clean, modified = mem_filter.filter_memory_write(raw_text)

    assert modified
    assert "[REDACTED_EMAIL]" in clean
    assert "sk-" not in clean

def test_tamper_detector():
    data = "Important Memory State"
    sig = TamperDetector.generate_signature(data)

    assert TamperDetector.verify_signature(data, sig)
    assert not TamperDetector.verify_signature("Tampered Data", sig)
