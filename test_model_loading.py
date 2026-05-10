#!/usr/bin/env python
"""Quick test of model loading."""

import sys

print("Testing LocalDetectionAgent...")
try:
    from autosecdev.agents.local_detection_agent import LocalDetectionAgent
    agent = LocalDetectionAgent()
    print(f"✓ Model loaded: {agent.is_loaded}")
    if agent.load_error:
        print(f"✗ Error: {agent.load_error}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\nTesting LocalPatchAgent...")
try:
    from autosecdev.agents.local_patch_agent import LocalPatchAgent
    patch_agent = LocalPatchAgent(detection_agent=agent)
    print(f"✓ Model loaded: {patch_agent.is_loaded}")
    if patch_agent.load_error:
        print(f"✗ Error: {patch_agent.load_error}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n✓ All models loaded successfully!")
