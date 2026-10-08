#!/usr/bin/env python3
"""
CYBERGUARD Accuracy Evaluation Script
====================================

Evaluates CYBERGUARD's URL threat detection pipeline against empirical datasets:
1. PhishTank: Ground-truth verified phishing URLs.
2. Tranco Top 1M: Ground-truth legitimate web domains.

Datasets are NOT tracked or committed to version control. They reside in `data/`.

Dataset Acquisition & Extraction Guide:
---------------------------------------
1. PhishTank Verified Online Feed:
   - Web: https://phishtank.org/developer_info.php
   - Direct CSV Download:
     curl -sS "https://data.phishtank.com/data/online-valid.csv" -o data/verified_online.csv
   - Expected columns: phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target

2. Tranco Top 1M List:
   - Web: https://tranco-list.eu/
   - Direct ZIP Download & Extraction:
     curl -sS "https://tranco-list.eu/top-1m.csv.zip" -o data/top-1m.csv.zip
     unzip -p data/top-1m.csv.zip top-1m.csv > data/top-1m.csv
   - Expected columns: rank, domain (header may or may not be present)

Usage:
------
  python scripts/evaluate_accuracy.py --n 5 --output test_results.csv
  python scripts/evaluate_accuracy.py --phishing data/verified_online.csv --legit data/top-1m.csv --n 100 --output results.csv
"""

import sys
import os
import csv
import time
import logging
import argparse
import urllib.parse
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional

# Ensure repository root and virtualenv site-packages are accessible
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# If running outside an active virtual environment, resolve .venv packages
venv_site_packages = list((REPO_ROOT / ".venv" / "lib").glob("python*/site-packages"))
if venv_site_packages and str(venv_site_packages[0]) not in sys.path:
    sys.path.insert(0, str(venv_site_packages[0]))

# Import CYBERGUARD detection and scoring components
from detection.url.detector import analyze_url, URLAnalysisResult
from app.backend.services.risk_engine import RiskEngine

# Optional Laya AI Adapter import
try:
    from app.backend.services.ai.laya_adapter import LayaAdapter
    LAYA_IMPORT_AVAILABLE = True
except Exception:
    LayaAdapter = None  # type: ignore
    LAYA_IMPORT_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_accuracy")


def load_phishing_urls(
    file_path: Path, max_count: int
) -> Tuple[List[str], Dict[str, int], int]:
    """
    Load up to max_count unique, valid HTTP/HTTPS phishing URLs from PhishTank CSV.

    Skips:
    - Empty or whitespace-only lines
    - Header row
    - Rows with missing or empty url field
    - URLs without http:// or https:// scheme
    - Malformed or unparseable URLs
    - Duplicate URLs

    Returns:
    (urls, skip_reasons_counter, total_rows_examined)
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Phishing dataset not found at: {file_path}")

    urls: List[str] = []
    seen: set = set()
    skip_counts: Dict[str, int] = {
        "empty_or_whitespace": 0,
        "missing_url_field": 0,
        "invalid_scheme": 0,
        "malformed_url": 0,
        "duplicate": 0,
        "parse_error": 0,
    }
    total_inspected = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames_lower = [col.strip().lower() for col in reader.fieldnames] if reader.fieldnames else []
        if "url" not in fieldnames_lower:
            actual_header = list(reader.fieldnames) if reader.fieldnames else []
            print(f"[ERROR] Expected column 'url' not found in {file_path}. Actual header row: {actual_header}")
            sys.exit(1)

        for row in reader:
            total_inspected += 1
            try:
                # Support case-insensitive key lookup for url column
                raw_url = row.get("url") or row.get("URL")
                if not raw_url:
                    skip_counts["missing_url_field"] += 1
                    continue

                cleaned_url = raw_url.strip()
                if not cleaned_url:
                    skip_counts["empty_or_whitespace"] += 1
                    continue

                # Must have explicit HTTP or HTTPS scheme
                lower_url = cleaned_url.lower()
                if not (lower_url.startswith("http://") or lower_url.startswith("https://")):
                    skip_counts["invalid_scheme"] += 1
                    continue

                # Basic RFC parsing check
                parsed = urllib.parse.urlsplit(cleaned_url)
                if not parsed.netloc:
                    skip_counts["malformed_url"] += 1
                    continue

                # Deduplicate
                if cleaned_url in seen:
                    skip_counts["duplicate"] += 1
                    continue

                seen.add(cleaned_url)
                urls.append(cleaned_url)

                if len(urls) >= max_count:
                    break

            except Exception:
                skip_counts["parse_error"] += 1
                continue

    return urls, skip_counts, total_inspected


def load_legitimate_urls(
    file_path: Path, max_count: int
) -> Tuple[List[str], Dict[str, int], int]:
    """
    Load up to max_count unique legitimate URLs by reading domains from Tranco CSV
    and prepending 'https://'.

    Skips:
    - Empty rows
    - Header rows ('rank', 'domain')
    - Domains missing a dot ('.')
    - Domains with invalid format
    - Duplicate domains

    Returns:
    (urls, skip_reasons_counter, total_rows_examined)
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Legitimate dataset not found at: {file_path}")

    urls: List[str] = []
    seen: set = set()
    skip_counts: Dict[str, int] = {
        "empty_or_whitespace": 0,
        "header_row": 0,
        "missing_dot": 0,
        "invalid_domain": 0,
        "duplicate": 0,
        "parse_error": 0,
    }
    total_inspected = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        # Detect whether the first line contains a header
        first_line = f.readline()
        f.seek(0)
        has_header = "domain" in first_line.lower()

        if has_header:
            reader = csv.DictReader(f)
            fieldnames_lower = [col.strip().lower() for col in reader.fieldnames] if reader.fieldnames else []
            if "domain" not in fieldnames_lower:
                actual_header = list(reader.fieldnames) if reader.fieldnames else []
                print(f"[ERROR] Expected column 'domain' not found in {file_path}. Actual header row: {actual_header}")
                sys.exit(1)
        else:
            # Check if first line is a header with unexpected columns (non-numeric first column)
            first_col = first_line.split(",")[0].strip()
            if first_col and not first_col.isdigit():
                reader = csv.DictReader(f)
                actual_header = list(reader.fieldnames) if reader.fieldnames else []
                print(f"[ERROR] Expected column 'domain' not found in {file_path}. Actual header row: {actual_header}")
                sys.exit(1)
            reader = csv.DictReader(f, fieldnames=["rank", "domain"])

        for row in reader:
            total_inspected += 1
            try:
                raw_domain = row.get("domain")
                if not raw_domain:
                    # Fallback to column index 1 if dict key was missing
                    if isinstance(row, dict) and None in row:
                        raw_domain = row[None][0] if row[None] else ""
                    else:
                        skip_counts["empty_or_whitespace"] += 1
                        continue

                cleaned_domain = raw_domain.strip().lower().rstrip("/")
                if not cleaned_domain:
                    skip_counts["empty_or_whitespace"] += 1
                    continue

                # Skip header row if encountered as data
                if cleaned_domain == "domain" or row.get("rank", "").strip().lower() == "rank":
                    skip_counts["header_row"] += 1
                    continue

                # Tranco rows with no dot in domain must be skipped
                if "." not in cleaned_domain or cleaned_domain.startswith(".") or cleaned_domain.endswith("."):
                    skip_counts["missing_dot"] += 1
                    continue

                # Strip existing scheme if present
                if "://" in cleaned_domain:
                    cleaned_domain = cleaned_domain.split("://", 1)[1]

                # Deduplicate
                if cleaned_domain in seen:
                    skip_counts["duplicate"] += 1
                    continue

                seen.add(cleaned_domain)
                constructed_url = f"https://{cleaned_domain}"
                urls.append(constructed_url)

                if len(urls) >= max_count:
                    break

            except Exception:
                skip_counts["parse_error"] += 1
                continue

    return urls, skip_counts, total_inspected


def evaluate_dataset(
    phishing_urls: List[str],
    legit_urls: List[str],
    threshold: int = 45,
    use_laya: bool = True,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """
    Run all URLs through CYBERGUARD's URL Analyzer and Laya (if available),
    scoring them via RiskEngine and comparing verdicts to ground-truth labels.
    """
    laya_adapter = None
    laya_available = False

    if use_laya and LAYA_IMPORT_AVAILABLE:
        try:
            laya_adapter = LayaAdapter()
            laya_available = laya_adapter.initialize()
            if laya_available:
                print("✓ Laya AI Decision Engine (CPU System 1) initialized successfully.")
            else:
                print("ℹ Laya AI unavailable; running in deterministic heuristics mode.")
        except Exception as exc:
            print(f"ℹ Laya initialization warning: {exc}. Using deterministic heuristics.")
            laya_adapter = None
            laya_available = False
    elif not use_laya:
        print("ℹ Laya AI disabled by user flag (--no-laya).")
    else:
        print("ℹ Laya AI package not installed; running in deterministic heuristics mode.")

    dataset = [("phishing", u) for u in phishing_urls] + [("legitimate", u) for u in legit_urls]
    results: List[Dict[str, Any]] = []

    print(f"\nEvaluating {len(dataset)} URLs ({len(phishing_urls)} phishing, {len(legit_urls)} legitimate)...")
    start_eval_time = time.time()

    for idx, (label, url) in enumerate(dataset, 1):
        try:
            # 1. Deterministic URL analysis
            det_result = analyze_url(url)

            # 2. Laya inference (if available)
            laya_res = {}
            if laya_available and laya_adapter:
                try:
                    laya_res = laya_adapter.analyze_url(det_result.normalized_url or url)
                except Exception as exc:
                    logger.debug("Laya error on %s: %s", url, exc)
                    laya_res = {"signals": {}, "findings": []}

            # 3. Risk calculation
            assessment = RiskEngine.calculate_risk(
                input_type="URL",
                target=det_result.normalized_url or url,
                detector_signals=det_result.signals,
                laya_signals=laya_res.get("signals", {}),
                qwen_signals={},
                external_intel_signals={},
                all_findings=det_result.findings + laya_res.get("findings", []),
            )

            score = assessment.score
            classification = assessment.classification

            # Verdict rule: score >= threshold -> phishing, otherwise legitimate
            verdict = "phishing" if score >= threshold else "legitimate"
            correct = (verdict == label)

            item = {
                "url": url,
                "label": label,
                "verdict": verdict,
                "correct": correct,
                "score": score,
                "classification": classification,
            }
            results.append(item)

            if verbose:
                mark = "✓" if correct else "✗"
                print(f"[{mark}] [{idx:4d}/{len(dataset)}] {label:10} -> {verdict:10} (score: {score:2d}) {url[:70]}")

        except Exception as exc:
            logger.error("Error evaluating URL '%s': %s", url, exc)
            results.append({
                "url": url,
                "label": label,
                "verdict": "error",
                "correct": False,
                "score": 0,
                "classification": "Error",
            })

    elapsed = time.time() - start_eval_time
    print(f"Evaluation completed in {elapsed:.2f} seconds ({elapsed / max(1, len(dataset)):.3f}s/URL).")
    return results


def print_evaluation_summary(
    results: List[Dict[str, Any]],
    phish_skips: Dict[str, int],
    phish_inspected: int,
    legit_skips: Dict[str, int],
    legit_inspected: int,
):
    """Compute and display confusion matrix, precision, recall, F1, and dataset metrics."""
    total = len(results)
    if total == 0:
        print("\n[!] No URLs were evaluated. Nothing to summarize.")
        return

    # Counts
    tp = sum(1 for r in results if r["label"] == "phishing" and r["verdict"] == "phishing")
    fn = sum(1 for r in results if r["label"] == "phishing" and r["verdict"] != "phishing")
    fp = sum(1 for r in results if r["label"] == "legitimate" and r["verdict"] == "phishing")
    tn = sum(1 for r in results if r["label"] == "legitimate" and r["verdict"] != "phishing")

    actual_phishing = tp + fn
    actual_legitimate = fp + tn

    # Metrics
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / total) if total > 0 else 0.0
    fpr = (fp / actual_legitimate) if actual_legitimate > 0 else 0.0

    print("\n| Metric | Value | Read |")
    print("|---|---|---|")
    print(f"| Accuracy | {accuracy * 100:.2f}% | Overall correctness |")
    print(f"| Precision | {precision * 100:.2f}% | Of flags raised, how many were right |")
    print(f"| Recall | {recall * 100:.2f}% | Of real phishing, how many caught |")
    print(f"| F1 | {f1 * 100:.2f}% | Balance of precision and recall |")
    print(f"| FPR | {fpr * 100:.2f}% | Of legitimate, how many wrongly flagged |")
    print(f"| True Positives | {tp} | Phishing correctly flagged |")
    print(f"| False Positives | {fp} | Legitimate wrongly flagged |")
    print(f"| True Negatives | {tn} | Legitimate correctly cleared |")
    print(f"| False Negatives | {fn} | Phishing missed |\n")
    print("Recall high and precision low means trigger-happy. Precision high and recall low means missing threats. Aim for both above 85%.\n")


def save_results_csv(output_path: Path, results: List[Dict[str, Any]]):
    """Write per-URL evaluation output to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["url", "label", "verdict", "correct", "score", "classification"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"✓ Saved per-URL results to: {output_path.resolve()} ({len(results)} rows)")


def main():
    parser = argparse.ArgumentParser(
        description="CYBERGUARD Accuracy Evaluation on PhishTank and Tranco Datasets"
    )
    parser.add_argument(
        "--phishing",
        default="data/verified_online.csv",
        type=str,
        help="Path to PhishTank verified_online.csv (default: data/verified_online.csv)",
    )
    parser.add_argument(
        "--legit",
        default="data/top-1m.csv",
        type=str,
        help="Path to Tranco top-1m.csv (default: data/top-1m.csv)",
    )
    parser.add_argument(
        "--n",
        default=100,
        type=int,
        help="Maximum number of URLs to evaluate per class (default: 100)",
    )
    parser.add_argument(
        "--output",
        default="results.csv",
        type=str,
        help="Output CSV file for per-URL results (default: results.csv)",
    )
    parser.add_argument(
        "--threshold",
        default=45,
        type=int,
        help="Risk score threshold to classify as phishing (default: 45)",
    )
    parser.add_argument(
        "--no-laya",
        action="store_true",
        default=False,
        help="Disable Laya neural engine, forcing pure deterministic analysis",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Print each URL evaluation verdict in real time",
    )

    args = parser.parse_args()

    phishing_path = Path(args.phishing)
    legit_path = Path(args.legit)
    output_path = Path(args.output)
    n = max(1, args.n)

    print("=" * 68)
    print("      CYBERGUARD BENCHMARK & ACCURACY EVALUATION RUNNER")
    print("=" * 68)
    print(f"• Phishing Source  : {phishing_path}")
    print(f"• Legitimate Source: {legit_path}")
    print(f"• Samples per Class: {n}")
    print(f"• Output File      : {output_path}")
    print(f"• Risk Threshold   : {args.threshold} (>= threshold classified as phishing)")

    # 1. Load Phishing URLs
    try:
        phish_urls, phish_skips, phish_inspected = load_phishing_urls(phishing_path, n)
        print(f"✓ Loaded {len(phish_urls)} unique phishing URLs from {phishing_path}")
    except Exception as exc:
        print(f"[ERROR] Failed to load phishing dataset: {exc}")
        sys.exit(1)

    # 2. Load Legitimate Domains and construct https:// URLs
    try:
        legit_urls, legit_skips, legit_inspected = load_legitimate_urls(legit_path, n)
        print(f"✓ Loaded {len(legit_urls)} unique legitimate URLs from {legit_path}")
    except Exception as exc:
        print(f"[ERROR] Failed to load legitimate dataset: {exc}")
        sys.exit(1)

    # 3. Run Evaluation Pipeline
    results = evaluate_dataset(
        phishing_urls=phish_urls,
        legit_urls=legit_urls,
        threshold=args.threshold,
        use_laya=not args.no_laya,
        verbose=args.verbose,
    )

    # 4. Save CSV Output
    save_results_csv(output_path, results)

    # 5. Display Summary Metrics & Confusion Matrix
    print_evaluation_summary(
        results=results,
        phish_skips=phish_skips,
        phish_inspected=phish_inspected,
        legit_skips=legit_skips,
        legit_inspected=legit_inspected,
    )


if __name__ == "__main__":
    main()
