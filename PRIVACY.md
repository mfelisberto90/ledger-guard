# Privacy policy

LedgerGuard is open-source, self-hosted reference software released under the MIT Licence.

## Data collection and telemetry

- **Zero outbound telemetry**: Neither the FastAPI server (`ledger_guard.api.app`) nor the Model Context Protocol `stdio` server (`ledger-guard-mcp`) phones home, sends analytics, or opens outbound network connections to third-party services.
- **Local `stdio` sandbox isolation**: Running `ledger-guard-mcp` (or `python -m ledger_guard`) creates an ephemeral in-memory ledger seeded with synthetic B2B product fixtures (`VALVE-DN50`, `REAGENT-BTL`, `INSTALL-SVC`). All state lives exclusively in local process memory and disappears when the process exits.
- **Self-hosted deployments**: Operators who deploy LedgerGuard in their own infrastructure control all database storage, authentication keys, and logs within their own environment. Built-in log redaction (`ledger_guard.security.redaction`) masks bearer tokens, secrets, and Luhn payment card sequences before diagnostic output is emitted.

## Contact

Questions regarding privacy or security handling can be reported via [GitHub Private Vulnerability Reporting](https://github.com/mfelisberto90/ledger-guard/security/advisories/new).
