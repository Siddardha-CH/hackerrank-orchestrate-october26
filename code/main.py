"""Ghost Data Still Exists - deletion audit agent.

Usage (from the repository root):
    python code/main.py                      # audit dataset/deletion_requests.csv -> ./output.csv
    python code/main.py --input dataset/sample_deletion_requests.csv --output sample_pred.csv
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from audit import intent, review, vision  # noqa: E402
from audit.data import read_csv  # noqa: E402
from audit.pipeline import Auditor, write_output, write_review_queue  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=os.path.join(ROOT, "dataset"))
    ap.add_argument("--input", default=None, help="requests CSV (default: dataset/deletion_requests.csv)")
    ap.add_argument("--output", default=os.path.join(ROOT, "output.csv"))
    ap.add_argument("--review-queue", default=os.path.join(ROOT, "review_queue.csv"),
                    help="cases flagged for a human reviewer (output.csv is unaffected)")
    ap.add_argument("--llm-review", action="store_true",
                    help="ask Claude for a second opinion on flagged cases (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--usage-json", default=os.path.join(HERE, "evaluation", "last_run_usage.json"))
    args = ap.parse_args(argv)

    t0 = time.time()
    req_path = args.input or os.path.join(args.dataset, "deletion_requests.csv")
    rows = read_csv(req_path)
    # Every participant-facing request shares one activity stream; the other request file is used as
    # context so that a workflow run is never attributed to the wrong person.
    others = [p for p in ("deletion_requests.csv", "sample_deletion_requests.csv")
              if os.path.abspath(os.path.join(args.dataset, p)) != os.path.abspath(req_path)]
    context = [r for p in others for r in read_csv(os.path.join(args.dataset, p))]

    auditor = Auditor(args.dataset)
    results = auditor.run(rows, context)
    write_output(results, args.output)
    queue = auditor.review
    if args.llm_review:
        queue = review.llm_review(queue, results, auditor.engine, auditor.engine.manifest)
    write_review_queue(queue, args.review_queue)

    usage = {
        "requests": len(rows),
        "seconds": round(time.time() - t0, 2),
        "vision": dict(vision.USAGE),
        "intent_llm": dict(intent.USAGE),
        "review_llm": dict(review.USAGE),
        "review_queue": len(queue),
        "calibration": auditor.engine.cal.summary(),
        "status_counts": {s: sum(1 for r in results if r["deletion_status"] == s)
                          for s in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")},
    }
    os.makedirs(os.path.dirname(args.usage_json), exist_ok=True)
    with open(args.usage_json, "w", encoding="utf-8") as fh:
        json.dump(usage, fh, indent=2)
    print(f"wrote {len(results)} rows to {args.output} in {usage['seconds']}s; "
          f"status={usage['status_counts']}; review queue={len(queue)}; "
          f"model calls={usage['vision']['calls'] + usage['intent_llm']['calls'] + usage['review_llm']['calls']}")


if __name__ == "__main__":
    main()
