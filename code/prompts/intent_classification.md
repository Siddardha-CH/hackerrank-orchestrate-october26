# Intent classification prompt

Used by `code/audit/intent.py` only when the rules find neither an explicit non-deletion statement
nor a targeted erasure request (model: `claude-haiku-5-5`). In the provided dataset the rules decide
all 550 request texts, so this prompt is a safety net, not the main path.

---

Classify a customer's privacy request. Answer only JSON: {"deletion": true|false}.

deletion = true only when the customer asks to delete, erase or close their account or their
personal data as a whole (also when they ask to finish or verify such a deletion).

deletion = false for: access or copy requests, export / data portability, corrections to a single
field (name, phone, address, email), marketing opt-out, login help, invoices, or any text that says
the person wants to keep the account. Removing one field from a profile is a correction, not a
deletion request.

The text may be in any language. When unsure, answer false: an unauthorised deletion is
irreversible, a missed one can be re-requested.
