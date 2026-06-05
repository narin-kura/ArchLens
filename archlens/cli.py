"""ArchLens CLI entry point."""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

from .engine import run_analysis
from .output.reporter import print_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="archlens",
        description="ArchLens — Architecture security & cost analyzer",
    )
    parser.add_argument(
        "source",
        help="Input: path to Terraform dir, draw.io file, cloud export JSON, or text description",
    )
    parser.add_argument(
        "--format",
        choices=["terraform", "drawio", "cloud-export", "text"],
        help="Force a specific parser (auto-detected if omitted)",
    )
    parser.add_argument(
        "--output",
        choices=["console", "json", "markdown"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--out-file",
        help="Write report to file instead of stdout",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv or sys.argv[1:])

    report = run_analysis(source=args.source, format_hint=args.format)
    print_report(report, output_format=args.output, out_file=args.out_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
