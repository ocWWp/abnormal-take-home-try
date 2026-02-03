#!/usr/bin/env python3
"""
Test script to verify OpenAI API key and generation works
"""

import sys

# Test API key - Set this to your OpenAI API key or set OPENAI_API_KEY environment variable
import os
API_KEY = os.environ.get("OPENAI_API_KEY", "")

print("=" * 60)
print("CommBridge AI - API Test Script")
print("=" * 60)

# Test 1: Check if openai is installed
print("\n[1/4] Checking if 'openai' package is installed...")
try:
    import openai
    print(f"✅ OpenAI package version: {openai.__version__}")
except ImportError as e:
    print(f"❌ OpenAI package not installed: {e}")
    print("   Run: pip install openai")
    sys.exit(1)

# Test 2: Check API key format
print("\n[2/4] Checking API key format...")
if API_KEY and API_KEY.startswith("sk-proj-"):
    print(f"✅ API key format looks correct (starts with 'sk-proj-')")
    print(f"   Length: {len(API_KEY)} characters")
else:
    print(f"❌ API key format incorrect")
    sys.exit(1)

# Test 3: Test simple API call
print("\n[3/4] Testing OpenAI API with simple call...")
try:
    from openai import OpenAI
    client = OpenAI(api_key=API_KEY)

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Say 'Hello World'"}],
        max_tokens=10
    )

    result = response.choices[0].message.content
    print(f"✅ API call successful!")
    print(f"   Response: {result}")
except Exception as e:
    print(f"❌ API call failed: {e}")
    print(f"   Error type: {type(e).__name__}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 4: Test with actual ground truth
print("\n[4/4] Testing with ground truth (like in the app)...")
try:
    ground_truth = """
    INCIDENT: Payment API failures detected at 10:15 AM EST
    ROOT CAUSE: Database connection pool exhausted
    IMPACT: 15% of payment requests failed
    FIX: Increased connection pool from 50 to 200
    RESOLUTION: All systems normal by 11:00 AM
    """

    system_prompt = """You are a technical communications writer.
Write a brief incident update based ONLY on the user's summary."""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Summary: {ground_truth}\n\nWrite a 2-sentence incident update."}
        ],
        temperature=0.3,
        max_tokens=150
    )

    draft = response.choices[0].message.content
    print(f"✅ Ground truth generation successful!")
    print(f"\n   Generated draft:")
    print(f"   {'-' * 58}")
    print(f"   {draft}")
    print(f"   {'-' * 58}")
except Exception as e:
    print(f"❌ Ground truth generation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("🎉 ALL TESTS PASSED! API is working correctly.")
print("=" * 60)
print("\nYou can now use the Streamlit app with confidence.")
print("Run: streamlit run app.py")
