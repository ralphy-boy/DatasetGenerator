#!/usr/bin/env python3
"""
Test script to verify imports for groq_dataset_generator.py

Run this to check if all required packages are available:
    python test_imports.py
"""

# Test imports
print("Testing imports...")

tests_passed = 0
tests_failed = 0

def test_import(name, import_name):
    global tests_passed, tests_failed
    try:
        __import__(import_name)
        print(f"✓ {name}")
        tests_passed += 1
    except ImportError as e:
        print(f"✗ {name}: {e}")
        tests_failed += 1

# Test required packages
test_import("groq", "groq")
test_import("requests", "requests")
test_import("beautifulsoup4", "bs4")
test_import("trafilatura", "trafilatura")
test_import("huggingface_hub", "huggingface_hub")
test_import("datasets", "datasets")

print(f"\n{tests_passed} passed, {tests_failed} failed")

if tests_failed > 0:
    print("\nInstall missing packages:")
    print("pip install groq requests beautifulsoup4 trafilatura huggingface-hub datasets")
    exit(1)

print("\n✓ All imports available!")
print("\nUsage:")
print("  # With Groq API key from https://console.groq.com/")
print('  GROQ_API_KEY=your_key python groq_dataset_generator.py --urls "https://..."')
print("")
print("  # Process local files")
print('  python groq_dataset_generator.py --files "/path/to/writeup.md"')
print("")
print("  # Upload to HuggingFace")
print('  python groq_dataset_generator.py --urls "..." --upload --repo-id user/dataset --hf-token $HF_TOKEN')