#!/usr/bin/env python
"""Test simple tokenizer loading."""

from transformers import AutoTokenizer

print("Testing tokenizer loading...")

# Try CodeBERT
print("\n1. CodeBERT:")
try:
    tok = AutoTokenizer.from_pretrained("microsoft/codebert-base", trust_remote_code=True)
    print(f"   OK: {type(tok)}")
except Exception as e:
    print(f"   ERROR: {e}")

# Try CodeT5 with different approach
print("\n2. CodeT5 (standard):")
try:
    tok = AutoTokenizer.from_pretrained("Salesforce/codet5-base", trust_remote_code=True)
    print(f"   OK: {type(tok)}")
except Exception as e:
    print(f"   ERROR: {e}")

# Try CodeT5 with use_fast=False
print("\n3. CodeT5 (use_fast=False):")
try:
    tok = AutoTokenizer.from_pretrained("Salesforce/codet5-base", use_fast=False, trust_remote_code=True)
    print(f"   OK: {type(tok)}")
except Exception as e:
    print(f"   ERROR: {e}")

# Try CodeT5 with legacy tokenizer
print("\n4. CodeT5 (legacy):")
try:
    from transformers import T5Tokenizer
    tok = T5Tokenizer.from_pretrained("Salesforce/codet5-base")
    print(f"   OK: {type(tok)}")
except Exception as e:
    print(f"   ERROR: {e}")
