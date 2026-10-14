# GWT-RPC-Checker

A Burp Suite extension for inspecting, decoding, mapping, and fuzzing Google Web Toolkit (GWT) RPC traffic.

This project provides a single-file Python extension that can run inside Burp's Jython environment and help security researchers and engineers analyze GWT-RPC requests and responses in a controlled, authorized workflow.

## What it does

- Decodes GWT-RPC request bodies and identifies service, strong name, interface, method, and parameter metadata
- Detects likely GWT-RPC request/response patterns in Burp history
- Pulls JavaScript bootstrap and permutation assets from application endpoints
- Maps JavaScript service names, method candidates, and generated hashes
- Fuzzes parameter values through Burp with configurable numeric and custom string payloads
- Compares alternate session/auth state against a baseline request
- Looks for token-like values and integrity checks in requests
- Identifies likely sensitive data, Java exception details, and stack traces in captured responses
- Extracts serialization policy and symbol map references from GWT assets

## Typical use cases

- Review a captured GWT-RPC request before sending mutations
- Test parameter handling for boundary conditions and malformed values
- Compare behavior between different sessions or authorization states
- Map application JavaScript and discover service endpoints
- Inspect support files such as `.gwt.rpc` and source map artifacts

## Requirements

- Burp Suite Professional or Community
- Jython standalone 2.7.x configured in Burp's Python environment settings
- A target application and account you are explicitly authorized to assess
- A captured GWT-RPC request or a valid GWT application bootstrap endpoint

## Repository contents

- `gwt_burp_extension.py` — the Burp extension implementation
- `requirement.md` — project requirements and workflow notes
- `tests/` — test fixtures used for regression/smoke checks

## Installation

1. Open Burp Suite.
2. Go to Extender -> Options.
3. Configure the Jython standalone runtime for your environment.
4. Go to Extender -> Extensions.
5. Add the extension and load `gwt_burp_extension.py`.
6. The extension adds a new tab named `GWT RPC` in Burp.

## Quick start

1. Capture a GWT-RPC request in Burp Proxy or HTTP history.
2. In Burp, right-click the request and choose `Send to GWT RPC Toolkit`.
3. Review the loaded request body in the `Payload / JavaScript` tab.
4. Click `Parse RPC` to decode the payload fields.
5. Optionally run `Map JavaScript` when working with bootstrap or cached JavaScript assets.
6. Add custom string payloads, set a numeric radius, and preview the fuzz count.
7. Enable `Allow active replay / mutation` when you intentionally want to send test requests.
8. Click `Fuzz Through Burp` and review results in the `Activity` tab.
9. Use the other result tabs (`Findings`, `Decoded`, `History`, `GWT Assets`, `Integrity Checks`, etc.) for deeper analysis.

## Supported workflow notes

The project includes support for:

- Decoding RPC request bodies
- Inspecting response envelopes and payload fields
- Parsing parameter types and indices
- Mapping JavaScript/bootstrap service names
- Fuzzing numeric and string values safely via Burp HTTP requests
- Comparing alternate session state and integrity-token behavior

For a detailed usage checklist and deeper workflow notes, see `requirement.md`.

## Safety and authorization

This tool is intended only for environments and systems you are explicitly authorized to test.

Active replay, mutation, and fuzzing can:

- create or modify application state
- trigger rate limits or security controls
- generate significant traffic
- produce side effects in production or shared environments

Use this tool responsibly and only against authorized targets.

## Troubleshooting

Common issues include:

- request not loaded from Burp history
- payload not recognized as a GWT-RPC message
- missing Jython runtime configuration
- no response available for a capture

If you are working with a request or response that does not parse correctly, verify that the selected body is a valid GWT-RPC payload and that the request was captured cleanly from Burp.

## Development notes

This repository is primarily a single-file Burp extension and is not packaged as a standalone Python library.

The project is built around Burp's native HTTP APIs and Jython interoperability rather than third-party dependencies.

## License

No explicit project license was found in the repository metadata. If you intend to redistribute or reuse this code, confirm the licensing terms before publication or commercial use.

## Contributing

Contributions are welcome if they improve compatibility, usability, or safety guidance. Since this project is tightly coupled to Burp and GWT-specific workflows, proposed changes should remain focused, well-documented, and accompanied by testing where possible.
