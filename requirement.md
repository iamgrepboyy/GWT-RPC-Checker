# GWT RPC Fuzzing Requirements

## Environment

- Burp Suite Professional or Community.
- Jython standalone 2.7.x configured in **Extender -> Options -> Python Environment**.
- The current `gwt_burp_extension.py` loaded in **Extender -> Extensions**.
- An application and test account that you are authorized to assess.

## Request Requirements

- A complete request captured by Burp Proxy or available in Burp HTTP history.
- A request body using the `text/x-gwt-rpc` content type.
- The request must include a valid HTTP service, host, port, and protocol.
- A saved response is recommended for comparing status codes and response sizes.
- The request should be selected from the extension's **History** tab before fuzzing.

## Fuzzing Workflow

1. Capture the GWT-RPC request in Burp.
2. Open the extension's **History** tab.
3. Select the target request.
4. Confirm the request body appears in **Payload / JavaScript**.
5. Review the decoded fields in the **Decoded** tab.
6. Add string payloads, one per line.
7. Set the numeric radius used around detected numeric values.
8. Click **Fuzz Through Burp**.
9. Review each generated request's HTTP status and response size in **Activity**.

## Payload Configuration

- String payloads are entered one per line.
- Empty lines are ignored.
- String payloads containing `|` are escaped because `|` separates GWT-RPC fields.
- Numeric fuzzing tests values below and above each detected numeric value, including the original value.
- The numeric radius must be between `1` and `1000`.

## Fuzzing Behavior

- The extension preserves the original request headers and HTTP service.
- `Content-Length` is rebuilt for every generated request.
- Generated requests are sent through Burp's `makeHttpRequest` API.
- Fuzzing runs in a background thread so Burp's Swing event-dispatch thread is not blocked.
- Results are recorded in the extension's Activity output.
- A preview shows the planned count under the configured hard cap.
- The default hard cap is 100 requests; the configurable range is 1 to 10,000.
- An optional delay paces requests; Stop Fuzz halts between requests.
- An explicit active-test opt-in is required before fuzzing or replay comparisons.
- Mutation candidates are based on parameter value indices in the captured RPC
	and decoded Java types; loaded serialization-policy types are labeled.

## Comparison Workflows

- Session comparison uses a selected captured request as the alternate source
	of authorization, cookie, and session/token headers, and compares its replay
	with the loaded baseline request.
- Integrity checks heuristically identify likely token headers, cookies, and
	RPC parameters. Selected candidates can be tested as missing or changed.
- Comparisons report HTTP status, GWT response envelope, body changes, and
	decoded response field changes. These differences are leads for manual
	verification, not vulnerability verdicts.
- Passive checks on captured GWT responses flag Java stack frames, exception
	details, and likely sensitive response fields; evidence is masked and
	requires manual context review.
- Integrity-token candidates also include URL query parameters and
	`application/x-www-form-urlencoded` fields.
## Regression and Smoke Tests

- Run fixture-backed checks with `python -m unittest discover -s tests -v`.
- The Burp/Jython smoke checklist is in `BURP_EXTENSION_USAGE.md`; it requires
	Burp configured with the Jython standalone runtime and an authorized
	disposable test endpoint.

## Safety and Authorization

Only fuzz systems, applications, accounts, and endpoints for which you have explicit authorization. Fuzzing can create state changes, trigger security controls, generate large amounts of traffic, or affect application availability.

## Troubleshooting

- If fuzzing reports that a full request is required, select the request from the **History** tab again.
- If no parameters are detected, confirm that the selected body is a complete GWT-RPC request.
- If Burp reports an HTTP-threading error, reload the latest extension file and verify that fuzzing is started with **Fuzz Through Burp**.
- If no response is available, confirm that Burp saved the response in HTTP history.
