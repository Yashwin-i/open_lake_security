#!/usr/bin/env python3
"""
run.py — Start OpenLake Security server
Usage:  python run.py
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        reload_excludes=[
            "temp_scan_zone/*",
            "temp_test_*/*",
            "data_lake/*",
            "boofuzz-results/*",
            ".venv/*",
            "venv/*",
            "__pycache__/*",
        ],
    )
