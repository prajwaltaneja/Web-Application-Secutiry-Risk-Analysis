#!/usr/bin/env python3
import sys
import os
import argparse

# Add package root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vapt_framework.core.config import load_targets
from vapt_framework.core.orchestrator import VAPTOrchestrator
from vapt_framework.modules.header_auditor import HeaderAuditor
from vapt_framework.analytics.risk_matrix import RiskMatrixEngine
from vapt_framework.analytics.attack_matrix import AttackMatrixEngine
from vapt_framework.analytics.exporter import MatrixExporter

BANNER = """
================================================================================
   ____                      ____                      _ _         
  / ___|   _ _ __  ___ _ __ / ___|  ___  ___ _   _ _ __(_) |_ _   _ 
 | |  | | | | '_ \\/ _ \\ '__/\\___ \\ / _ \\/ __| | | | '__| | __| | | |
 | |__| |_| | |_) | __/ |    ___) |  __/ (__| |_| | |  | | |_| |_| |
  \\____\\__, | .__/ \\___|_|   |____/ \\___|\\___|\\__,_|_|  |_|\\__|\\__, |
       |___/|_|                                                |___/ 
      CYBER SECURITY RISK ANALYSIS IN WEB APPLICATIONS (VAPT)
  Cryptocurrency & Web3 Platform Vulnerability Assessment Framework
================================================================================
  B.Tech Major Project - Maharaja Surajmal Institute of Technology (GGSIPU)
  Authors: Prajwal Taneja (07215002718), Priyam Gautam (07815002718), Ambar Hajela (35115002718)
  Project Mentor: Dr. Priyanka Nandal, Associate Professor, MSIT CSE
================================================================================
"""

def print_project_info():
    print(BANNER)
    print("Project Scope: Security assessment of 10 cryptocurrency exchanges & wallets.")
    print("Target Systems:")
    targets = load_targets()
    for t in targets:
        print(f"  * [{t.type.value.upper()}] {t.name:<30} {t.url:<36} ({t.architecture.value})")
    print("\n10 Investigated Vulnerability Classes:")
    print("  1. CSP: wildcard directive               6. Cross-domain JS source inclusion")
    print("  2. CSP: style-src unsafe inline         7. Secure pages include mixed content")
    print("  3. CSP: script-src unsafe inline        8. Cookie without same site attribute")
    print("  4. X-frame options header not set        9. Incomplete or no cache control")
    print("  5. Absence of anti CSRF tokens          10. X-content type option header missing")
    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(
        description="VAPT and Cyber Security Risk Analysis Framework for Cryptocurrency Web Platforms",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # info
    subparsers.add_parser("info", help="Display project background, thesis metadata, and authors")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Run security audit against a live target URL")
    audit_parser.add_argument("--url", required=True, help="Target URL to evaluate (e.g. https://crypto.com)")

    # matrix
    matrix_parser = subparsers.add_parser("matrix", help="Generate Risk Matrix (Fig 30) or Attack Matrix (Fig 31)")
    matrix_parser.add_argument("--type", choices=["risk", "attack", "both"], default="both", help="Matrix type to display")
    matrix_parser.add_argument("--format", choices=["markdown", "csv", "json"], default="markdown", help="Output format")

    # export
    export_parser = subparsers.add_parser("export", help="Export empirical matrices into reports/generated/")
    export_parser.add_argument("--out-dir", default=None, help="Output directory for generated matrices")

    # list-targets
    subparsers.add_parser("list-targets", help="List all evaluated cryptocurrency targets")

    args = parser.parse_args()

    if not args.command or args.command == "info" or args.command == "list-targets":
        print_project_info()
        return

    if args.command == "matrix":
        if args.type in ["risk", "both"]:
            print("\n=== EMPIRICAL RISK MATRIX (Figure 30) ===")
            risk_eng = RiskMatrixEngine()
            if args.format == "markdown":
                print(risk_eng.to_markdown())
            elif args.format == "csv":
                print(risk_eng.to_csv())
            elif args.format == "json":
                print(risk_eng.to_json())

        if args.type in ["attack", "both"]:
            print("\n=== VULNERABILITY VS ATTACK MATRIX (Figure 31) ===")
            attack_eng = AttackMatrixEngine()
            if args.format == "markdown":
                print(attack_eng.to_markdown())
            elif args.format == "csv":
                print(attack_eng.to_csv())
            elif args.format == "json":
                print(attack_eng.to_json())

    elif args.command == "audit":
        print(f"[*] Initiating Security Header & Client Protection Audit against {args.url}...")
        auditor = HeaderAuditor()
        findings = auditor.audit_target(args.url)
        print(f"[+] Audit complete. Found {len(findings)} security findings:")
        for idx, f in enumerate(findings, 1):
            sev_badge = f"[{f.severity.value.upper()}]"
            print(f"  {idx:02d}. {sev_badge:<8} {f.title}")
            print(f"      Description : {f.description}")
            if f.evidence:
                print(f"      Evidence    : {f.evidence[:120]}")
            print(f"      Remediation : {f.remediation}")
            print("")

    elif args.command == "export":
        out_dir = args.out_dir or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "reports", "generated")
        )
        print(f"[*] Exporting matrices to {out_dir}...")
        MatrixExporter.export_all(out_dir)

if __name__ == "__main__":
    main()
