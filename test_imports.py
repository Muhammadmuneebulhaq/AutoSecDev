#!/usr/bin/env python
"""Test that imports work without downloading models."""

import sys

print("Testing imports...")
try:
    from autosecdev.agents.local_detection_agent import LocalDetectionAgent
    print("✓ LocalDetectionAgent imported")
except Exception as e:
    print(f"✗ LocalDetectionAgent import failed: {e}")
    sys.exit(1)

try:
    from autosecdev.agents.local_patch_agent import LocalPatchAgent
    print("✓ LocalPatchAgent imported")
except Exception as e:
    print(f"✗ LocalPatchAgent import failed: {e}")
    sys.exit(1)

print("\n✓ All imports successful!")
