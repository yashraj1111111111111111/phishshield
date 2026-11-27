"""Prepare a clean, deduplicated url,label dataset at data/processed/phishing_urls.csv."""
from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

csv.field_size_limit(min(sys.maxsize, 10_000_000))

RAW_DEFAULT = Path("data/raw/phishing_urls.csv")
PROCESSED_DEFAULT = Path("data/processed/phishing_urls.csv")

BENIGN_HOSTS = [
    "www.example.com",
    "docs.example.org",
    "portal.example.edu",
    "library.example.net",
    "help.example.com",
    "status.example.org",
    "mail.example.net",
    "campus.example.edu",
]
BENIGN_PATHS = [
    "",
    "/about",
    "/courses/2026",
    "/support/faq",
    "/blog/security-tips",
    "/account/settings",
    "/login",
    "/update-profile",
    "/docs/getting-started/overview/guide",
]
PHISH_BRANDS = ["paypal", "amazon", "sbi", "hdfc", "apple", "google", "netflix", "microsoft"]
PHISH_TOKENS = ["verify", "login", "secure", "account", "update", "free", "bonus"]
SHORTENER_HOSTS = ["bit.ly", "tinyurl.com", "t.co", "is.gd"]
TEST_NET_IPS = ["192.0.2", "198.51.100", "203.0.113"]


def _normalize_label(raw_label: str) -> int | None:
    value = raw_label.strip().lower()
    if value in {"0", "benign", "legitimate", "safe"}:
        return 0
    if value in {"1", "phishing", "malicious", "bad"}:
        return 1
    return None


def prepare_from_raw(raw_path: Path, invert_labels: bool = False) -> list[tuple[str, int]]:
    """Read and deduplicate a raw CSV with url and label columns."""
    seen: set[str] = set()
    rows: list[tuple[str, int]] = []
    with raw_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        field_map = {name.strip().lower(): name for name in (reader.fieldnames or [])}
        url_col = field_map.get("url")
        label_col = field_map.get("label")
        if not url_col or not label_col:
            raise SystemExit(f"Raw CSV {raw_path} must contain 'url' and 'label' columns.")
        for record in reader:
            url = (record.get(url_col) or "").strip()
            label = _normalize_label(record.get(label_col) or "")
            if not url or label is None or url in seen:
                continue
            if invert_labels:
                label = 1 - label
            seen.add(url)
            rows.append((url, label))
    return rows


def generate_reserved_baseline(count_per_class: int = 600, seed: int = 42) -> list[tuple[str, int]]:
    """Generate a safe synthetic benchmark using RFC 2606/5737 reserved domains and IPs."""
    rng = random.Random(seed)
    seen: set[str] = set()
    rows: list[tuple[str, int]] = []

    def add_unique(url: str, label: int) -> None:
        if url not in seen:
            seen.add(url)
            rows.append((url, label))

    attempts = 0
    while sum(1 for _, lbl in rows if lbl == 0) < count_per_class and attempts < count_per_class * 10:
        attempts += 1
        host = rng.choice(BENIGN_HOSTS)
        path = rng.choice(BENIGN_PATHS)
        scheme = "http" if rng.random() < 0.08 else "https"
        query = f"?ref={rng.randint(100, 999)}" if rng.random() < 0.25 else ""
        if rng.random() < 0.12:
            query += f"&page={rng.randint(1, 50)}" if query else f"?page={rng.randint(1, 50)}"
        add_unique(f"{scheme}://{host}{path}{query}", 0)

    attempts = 0
    while sum(1 for _, lbl in rows if lbl == 1) < count_per_class and attempts < count_per_class * 10:
        attempts += 1
        pattern = rng.choice(["ip", "lookalike", "shortener", "encoded"])
        tok1, tok2 = rng.sample(PHISH_TOKENS, 2)
        if pattern == "ip":
            prefix = rng.choice(TEST_NET_IPS)
            host = f"{prefix}.{rng.randint(1, 254)}"
            scheme = "http" if rng.random() < 0.85 else "https"
            url = f"{scheme}://{host}/{tok1}/{tok2}?id={rng.randint(1000, 9999)}"
        elif pattern == "lookalike":
            brand = rng.choice(PHISH_BRANDS)
            tld = rng.choice(["example", "test"])
            scheme = "http" if rng.random() < 0.65 else "https"
            host = f"{brand}-{tok1}-alert.auth.{tld}"
            url = f"{scheme}://{host}/{tok2}/session?token={rng.randint(10000, 99999)}"
        elif pattern == "shortener":
            host = rng.choice(SHORTENER_HOSTS)
            url = f"https://{host}/{tok1}{rng.randint(100, 9999)}"
        else:
            brand = rng.choice(PHISH_BRANDS)
            url = f"http://{brand}-portal.example/{tok1}%2F{tok2}%3Fnext%3D{rng.randint(1, 99)}"
        add_unique(url, 1)

    rng.shuffle(rows)
    return rows


def write_processed_csv(rows: list[tuple[str, int]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "label"])
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare phishing_urls.csv for MLP training.")
    parser.add_argument("--raw", type=Path, default=None, help="Optional raw CSV with url,label columns.")
    parser.add_argument("--invert-labels", action="store_true", help="Flip 0/1 labels (e.g., UCI PhiUSIIL uses 1=legitimate, 0=phishing).")
    parser.add_argument("--output", type=Path, default=PROCESSED_DEFAULT, help="Output processed CSV path.")
    parser.add_argument("--per-class", type=int, default=600, help="Samples per class for synthetic baseline.")
    args = parser.parse_args()

    raw_path = args.raw or (RAW_DEFAULT if RAW_DEFAULT.exists() else None)
    if raw_path is not None:
        rows = prepare_from_raw(raw_path, invert_labels=args.invert_labels)
        source_desc = str(raw_path)
    else:
        rows = generate_reserved_baseline(count_per_class=args.per_class)
        source_desc = "synthetic RFC 2606/5737 baseline"

    write_processed_csv(rows, args.output)
    positives = sum(1 for _, label in rows if label == 1)
    negatives = len(rows) - positives
    print(f"Prepared {len(rows)} rows ({negatives} benign, {positives} phishing) from {source_desc} -> {args.output}")


if __name__ == "__main__":
    main()
