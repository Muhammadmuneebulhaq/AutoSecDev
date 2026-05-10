#!/usr/bin/env python
"""Test tokenizer compatibility."""

import sys

print("Testing tokenizer compatibility...")

# Test CodeBERT tokenizer
try:
    from transformers import AutoTokenizer
    
    print("\n1. Testing CodeBERT tokenizer...")
    codebert_tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    
    snippet = "def unsafe_eval(x):\n    return eval(x)"
    
    # Test with list (new approach)
    try:
        inputs = codebert_tokenizer([snippet], return_tensors="pt", truncation=True, max_length=512)
        print("   [OK] CodeBERT tokenizer works with list input")
    except Exception as e:
        print(f"   [WARN] CodeBERT list input failed: {e}")
        # Try without list
        inputs = codebert_tokenizer(snippet, return_tensors="pt", truncation=True, max_length=512)
        print("   [OK] CodeBERT tokenizer works with string input")
    
except Exception as e:
    print(f"[ERROR] CodeBERT tokenizer test failed: {e}")
    sys.exit(1)

# Test CodeT5 tokenizer
try:
    print("\n2. Testing CodeT5 tokenizer...")
    codet5_tokenizer = AutoTokenizer.from_pretrained("Salesforce/codet5-base")
    
    prompt = "Fix vulnerability:\n### Vulnerable code:\ndef unsafe_eval(x):\n    return eval(x)\n### Fixed code:"
    
    # Test with list (new approach)
    try:
        inputs = codet5_tokenizer([prompt], return_tensors="pt", truncation=True, max_length=512)
        print("   [OK] CodeT5 tokenizer works with list input")
    except Exception as e:
        print(f"   [WARN] CodeT5 list input failed: {e}")
        # Try without list
        inputs = codet5_tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
        print("   [OK] CodeT5 tokenizer works with string input")
    
except Exception as e:
    print(f"[ERROR] CodeT5 tokenizer test failed: {e}")
    sys.exit(1)

print("\n[OK] All tokenizers working!")

