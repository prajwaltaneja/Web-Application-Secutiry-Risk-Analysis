#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vapt_framework.analytics.exporter import MatrixExporter

if __name__ == "__main__":
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports", "generated"))
    print(f"[*] Regenerating and exporting all matrices to {out_dir}...")
    MatrixExporter.export_all(out_dir)
    print("[+] Done!")
