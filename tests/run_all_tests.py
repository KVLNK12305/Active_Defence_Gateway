#!/usr/bin/env python3
"""
run_all_tests.py

Reproducible Test Inventory & Execution Suite for ADG Framework.
Executes all Python unit/integration tests and Rust cargo tests,
generating an itemized test inventory report.
"""

import unittest
import subprocess
import os
import sys

def run_python_tests():
    print("======================================================================")
    print("1. DISCOVERING & RUNNING PYTHON TEST SUITE")
    print("======================================================================")
    loader = unittest.TestLoader()
    tests_dir = os.path.dirname(__file__)
    suite = loader.discover(tests_dir, pattern="test_*.py")
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    total_python = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    passed_python = total_python - failures - errors
    
    print(f"\nPython Test Summary: {passed_python}/{total_python} PASSED ({failures} failures, {errors} errors)")
    return passed_python, total_python, result

def run_rust_tests():
    print("\n======================================================================")
    print("2. EXECUTING RUST CORE TEST SUITE")
    print("======================================================================")
    rust_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../adg-xdp/adg-xdp"))
    
    # Locate test binary
    deps_dir = os.path.abspath(os.path.join(rust_dir, "../target/debug/deps"))
    test_binary = None
    if os.path.exists(deps_dir):
        candidates = sorted(
            [f for f in os.listdir(deps_dir) if f.startswith("adg_xdp-") and "." not in f],
            key=lambda f: os.path.getmtime(os.path.join(deps_dir, f)),
            reverse=True
        )
        for f in candidates:
            full_path = os.path.join(deps_dir, f)
            if os.access(full_path, os.X_OK):
                # Check if binary runs unit tests
                res = subprocess.run([full_path, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if "test runner" in res.stdout.lower() or "usage: " in res.stdout.lower() or "tests" in res.stdout.lower():
                    test_binary = full_path
                    break
                
    if not test_binary:
        print("Rust test binary not found. Compiling with cargo...")
        cmd = ["cargo", "test", "--no-run"]
        subprocess.run(cmd, cwd=rust_dir, check=True)
        for f in os.listdir(deps_dir):
            full_path = os.path.join(deps_dir, f)
            if f.startswith("adg_xdp-") and "." not in f and os.access(full_path, os.X_OK):
                test_binary = full_path
                break

    print(f"Executing Rust test binary: {test_binary}")
    res = subprocess.run([test_binary, "--nocapture"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    combined_output = (res.stdout or "") + "\n" + (res.stderr or "")
    lines = combined_output.splitlines()
    summary_line = [l for l in lines if "test result:" in l]
    
    summary_text = summary_line[0] if summary_line else f"Returncode {res.returncode}"
    print(f"Rust Output Summary: {summary_text}")
    return res.returncode == 0, summary_text

def main():
    py_passed, py_total, py_res = run_python_tests()
    rust_ok, rust_summary = run_rust_tests()
    
    print("\n======================================================================")
    print("REPRODUCIBLE TEST INVENTORY & VERIFICATION REPORT")
    print("======================================================================")
    print(f"Python Test Suite: {py_passed}/{py_total} Passed")
    print(f"Rust Test Suite:   {rust_summary}")
    print("----------------------------------------------------------------------")
    if py_passed == py_total and rust_ok:
        print("SYSTEM VERIFICATION STATUS: 100% PASS SUCCESS")
        sys.exit(0)
    else:
        print("SYSTEM VERIFICATION STATUS: FAILURE DETECTED")
        sys.exit(1)

if __name__ == "__main__":
    main()
