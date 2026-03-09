from scanners.fuzz_analysis import run_fuzz_scan

if __name__ == "__main__":
    result = run_fuzz_scan("target_app")
    print("\n[TEST RESULT]")
    import json
    print(json.dumps(result, indent=4))
