# Token usage and cost - final full-dataset run

Run: `python code/main.py` over `dataset/deletion_requests.csv` (518 requests), wall time 0.79 s, statuses {'COMPLETE': 149, 'INCOMPLETE': 359, 'NOT_APPLICABLE': 10}.

## Final run (the run that produced `output.csv`)

| Provider | Model | Purpose | Calls | Input tokens | Output tokens | Total tokens | Est. cost |
|---|---|---|---|---|---|---|---|
| Anthropic | claude-opus-5-5 | screenshot extraction (cache miss only) | 0 | 0 | 0 | 0 | $0.00 |
| Anthropic | claude-haiku-5-5 | intent fallback when rules are undecided | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | | | **0** | **0** | **0** | **0** | **$0.00** |

- Average tokens per request: **0.0**; estimated cost per request: **$0.0000**.
- Screenshot extractions served from the content-hashed cache: 11 of 11 images.
- All 518 decisions were produced by the deterministic reasoning core (identity resolution, evidence normalisation, workflow attribution, policy and planning), so the run is reproducible bit-for-bit.

## One-off multimodal extraction (development time)

The 11 application screenshots under `dataset/evidence/images/` were transcribed once with Claude (`claude-opus-5-5`, Anthropic) using `VISION_PROMPT` in `code/audit/vision.py`; results are stored in `code/audit/vision_cache.json` keyed by SHA-256 of the image. PDFs are read locally with `pypdf` (no model).

| Provider | Model | Calls | Input tokens (est.) | Output tokens (est.) | Total (est.) | Est. cost |
|---|---|---|---|---|---|---|
| Anthropic | claude-opus-5-5 | 11 | ~33,000 (11 x ~2.9k image + prompt) | ~5,500 (11 x ~500) | ~38,500 | ~$0.30 |

Token estimates use the image-token rule of thumb (width x height / 750 for 1800x1200 px screenshots) and list-price assumptions of $5 / M input and $25 / M output tokens; they are estimates, not billing records. Amortised over 518 requests this is ~74 tokens and ~$0.0006 per request. If the cache is deleted and `ANTHROPIC_API_KEY` is set, the same extraction runs live and the real counts are recorded in `code/evaluation/last_run_usage.json` and this table.

## Why so few tokens

Evidence is mostly structured (SQL, JSON, key=value logs). Parsing it deterministically is cheaper, exact and auditable; model calls are reserved for the genuinely unstructured inputs (screenshots) and cached by content hash, and for intent texts the rules cannot decide (none in this dataset).
