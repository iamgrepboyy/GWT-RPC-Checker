import ast
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
EXTENSION = ROOT / "gwt_burp_extension.py"


def load_pure_classes():
    tree = ast.parse(EXTENSION.read_text(encoding="utf-8"))
    wanted = {"GwtRpc", "GwtResponse", "GwtMessageDecoder",
              "GwtSensitiveFinder", "GwtResponseFinder"}
    classes = [node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name in wanted]
    namespace = {"json": json}
    module = ast.Module(body=classes, type_ignores=[])
    exec(compile(module, str(EXTENSION), "exec"), namespace)
    return namespace


PURE = load_pure_classes()
GwtRpc = PURE["GwtRpc"]
GwtResponse = PURE["GwtResponse"]
GwtMessageDecoder = PURE["GwtMessageDecoder"]
GwtResponseFinder = PURE["GwtResponseFinder"]


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8").strip()


class GwtRpcRegressionTests(unittest.TestCase):
    def test_string_parameter_uses_data_table_value_offset(self):
        parsed = GwtRpc(fixture("gwt_rpc_string_request.txt")).parse()

        self.assertIsNone(parsed.error)
        self.assertEqual(parsed.interface_name, "example.Service")
        self.assertEqual(parsed.method_name, "method")
        self.assertEqual(parsed.parameters[0]["type"], "java.lang.String")
        self.assertEqual(parsed.parameters[0]["value"], "hello")

        mutations = parsed.fuzz_payloads(["custom"], 2, ["java.lang.String"], 10)
        self.assertTrue(mutations)
        for _, payload in mutations:
            self.assertEqual(payload.split("|")[7], "java.lang.String")
            self.assertNotEqual(payload.split("|")[8], "hello")

    def test_numeric_mutation_obeys_generation_limit(self):
        parsed = GwtRpc(fixture("gwt_rpc_integer_request.txt")).parse()
        mutations = parsed.fuzz_payloads([], 5, [], 3)

        self.assertEqual(parsed.parameters[0]["value"], "12")
        self.assertEqual(len(mutations), 3)
        self.assertTrue(all(payload.split("|")[7] == "java.lang.Integer"
                            for _, payload in mutations))
        self.assertTrue(all(payload.split("|")[8] != "java.lang.Integer"
                            for _, payload in mutations))

    def test_response_comparison_reports_changed_decoded_fields(self):
        baseline_text = fixture("gwt_rpc_response_baseline.txt")
        changed_text = fixture("gwt_rpc_response_changed.txt")
        baseline_envelope, baseline_payload = GwtResponse.decode(baseline_text)
        changed_envelope, changed_payload = GwtResponse.decode(changed_text)

        comparison = GwtResponse.compare(
            {"body": baseline_text, "payload": baseline_payload},
            {"body": changed_text, "payload": changed_payload})

        self.assertEqual(baseline_envelope, "OK")
        self.assertEqual(changed_envelope, "OK")
        self.assertTrue(comparison["body_changed"])
        self.assertEqual(comparison["changed_paths"], ["response[0]", "response[1]"])

    def test_message_editor_decoder_formats_gwt_request_and_response(self):
        request = GwtMessageDecoder.decode_request(fixture("gwt_rpc_string_request.txt"))
        response = GwtMessageDecoder.decode_response(
            fixture("gwt_rpc_response_baseline.txt"))

        self.assertIn("Interface: example.Service", request)
        self.assertIn("Method: method", request)
        self.assertIn("Parameter 1 (java.lang.String, index 6): hello", request)
        self.assertIn("Envelope: OK", response)
        self.assertIn("response[0]: record-1", response)
        self.assertIsNone(GwtMessageDecoder.decode_response("ordinary response"))

    def test_passive_response_scanner_finds_stack_and_exception_details(self):
        findings = GwtResponseFinder.find(
            "java.lang.IllegalStateException: failed\n"
            "    at example.Service.run(Service.java:42)\n"
            '{"access_token":"abcdef1234567890"}')
        categories = set(item[0] for item in findings)

        self.assertIn("Java stack trace", categories)
        self.assertIn("Java exception detail", categories)
        self.assertIn("Possible sensitive response field", categories)
        self.assertNotIn("abcdef1234567890", " ".join(item[1] for item in findings))


if __name__ == "__main__":
    unittest.main()
