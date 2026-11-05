UNIFIED TIP UPGRADE BUNDLE v3
=============================

This update improves MISP response parsing for nested API response envelopes and
ensures direct Feodo-to-MISP query results are merged into the unified indicator
records, even when bulk MISP pagination is incomplete.

Files to replace in ~/misp-aggregator:
- unified_ingest.py
- dashboard_unified.py (unchanged from v2; included for convenience)
- run_unified_tip.sh (unchanged from v2; included for convenience)

Keep .env, .venv, Feodo source files, and existing main.py unchanged.

Install:
  cd ~/misp-aggregator
  # Copy the three files from this archive into this directory, replacing files.
  chmod +x run_unified_tip.sh
  ./run_unified_tip.sh
  python -m json.tool unified_tip_report.json

The report's misp_bulk_retrieval_complete remains false when the safety cap is
reached. This version does not claim to retrieve all MISP attributes when capped.
It does not enable, fetch, or modify configured external feeds.

TLS verification remains configurable via MISP_VERIFY_TLS in .env. For a lab
self-signed certificate, false may be needed; use trusted certificate validation
outside the lab.
