"""Test runner for SentinelAgent."""

import sys
import pytest


def run_tests():
    """Run all tests."""
    print("=" * 60)
    print("Running SentinelAgent Tests")
    print("=" * 60)
    
    # Run tests with coverage
    args = [
        "-v",
        "--tb=short",
        "-p",
        "no:cacheprovider",
        "tests/"
    ]
    
    exit_code = pytest.main(args)
    
    print("=" * 60)
    if exit_code == 0:
        print("All tests passed!")
    else:
        print(f"Tests failed with exit code: {exit_code}")
    print("=" * 60)
    
    return exit_code


if __name__ == "__main__":
    sys.exit(run_tests())
