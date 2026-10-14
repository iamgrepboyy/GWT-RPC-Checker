# -*- coding: utf-8 -*-
"""Single-file Burp Suite extension for the GWT toolset.

Compatible with Burp's Jython 2.7 extension runtime.  No third-party modules
or repository files are required; HTTP is sent through Burp's own HTTP service.

Load this file directly in Burp Extender. It replaces the command-line
enumerator, mapper, parser, and fuzzer workflows in the original scripts.
"""

from java.awt import BorderLayout, Dimension, Font, GridLayout
from java.awt import Color
from java.awt.event import ActionListener, MouseAdapter
from java.lang import Runnable, Thread
from java.io import File, FileWriter, PrintWriter
from java.net import URL, URLDecoder, URLEncoder
from java.util.concurrent.atomic import AtomicBoolean
import json
from javax.swing import JButton, JCheckBox, JFileChooser, JLabel, JMenuItem, JPanel, JScrollPane
from javax.swing import JSplitPane, JSpinner, JTable, JTabbedPane, JTextArea, SpinnerNumberModel
from javax.swing import JTextField
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing import SwingUtilities
from javax.swing.event import ListSelectionListener
from javax.swing.table import DefaultTableCellRenderer, DefaultTableModel
from java.util import Comparator

from burp import IBurpExtender, IContextMenuFactory, IHttpListener, IMessageEditorController
from burp import IMessageEditorTab, IMessageEditorTabFactory, IProxyListener, ITab


class _Action(ActionListener):
    def __init__(self, function):
        self.function = function

    def actionPerformed(self, event):
        self.function()


class _TabSelection(MouseAdapter):
    def __init__(self, tabs, index):
        self.tabs = tabs
        self.index = index

    def mousePressed(self, event):
        self.tabs.setSelectedIndex(self.index)


class _ExpandedTabLabel(JLabel):
    def __init__(self, tabs, index, title):
        JLabel.__init__(self, title)
        self.tabs = tabs
        self.index = index
        self.setHorizontalAlignment(JLabel.CENTER)
        self.setOpaque(False)
        self.setToolTipText(title)
        self.addMouseListener(_TabSelection(tabs, index))

    def getPreferredSize(self):
        return JLabel.getPreferredSize(self)


class _Selection(ListSelectionListener):
    def __init__(self, function):
        self.function = function

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.function()


class _DecodedCellRenderer(DefaultTableCellRenderer):
    REQUEST_COLOR = Color(24, 69, 112)
    RESPONSE_COLOR = Color(27, 92, 55)

    def getTableCellRendererComponent(self, table, value, selected, focused, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focused, row, column)
        part = str(table.getValueAt(row, 0))
        is_response = (part == "HTTP status" or part == "GWT envelope" or
                       part == "Response payload" or part.startswith("response["))
        component.setBackground(self.RESPONSE_COLOR if is_response else self.REQUEST_COLOR)
        component.setForeground(Color.WHITE)
        return component


class _UiUpdate(Runnable):
    def __init__(self, function):
        self.function = function

    def run(self):
        self.function()


class _BackgroundTask(Runnable):
    def __init__(self, function):
        self.function = function

    def run(self):
        self.function()


class _NumericComparator(Comparator):
    def compare(self, left, right):
        try:
            left_value = int(str(left))
            right_value = int(str(right))
            return -1 if left_value < right_value else (1 if left_value > right_value else 0)
        except (TypeError, ValueError):
            return 0 if str(left) == str(right) else (-1 if str(left) < str(right) else 1)


class GwtRpc(object):
    """Small, defensive parser for the GWT RPC wire format."""

    def __init__(self, payload):
        self.payload = payload or ""
        self.parts = self.payload.split("|")
        self.fuzzable = []
        self.host = ""
        self.strong_name = ""
        self.interface_name = ""
        self.method_name = ""
        self.parameters = []
        self.error = None

    def parse(self):
        if len(self.parts) < 8:
            self.error = "Not a GWT-RPC payload"
            return self
        try:
            columns = int(self.parts[2])
            data = [""] + self.parts[3:3 + columns]
            indices = self.parts[3 + columns:]
            if len(data) < 7:
                raise ValueError("missing data table")
            self.host = data[1]
            self.strong_name = data[2]
            self.interface_name = data[3]
            self.method_name = data[4]
            self._mark_indices(indices, data, len(data), columns)
        except (ValueError, IndexError):
            self.error = "Malformed GWT-RPC payload"
        return self

    def _mark_indices(self, indices, data, data_length, columns):
        if not indices:
            return
        try:
            parameter_count = int(indices[0])
        except ValueError:
            return
        cursor = 1
        for _ in range(parameter_count):
            if cursor >= len(indices):
                break
            type_index = self._to_int(indices[cursor])
            cursor += 1
            type_name = ""
            if type_index is not None and type_index < data_length:
                type_name = data[type_index]
            value_index = self._to_int(indices[cursor]) if cursor < len(indices) else None
            if value_index is not None:
                self.fuzzable.append((value_index, "%s" % value_index))
            value = data[value_index] if value_index is not None and 0 <= value_index < data_length else ""
            cursor += 1
            self.parameters.append({"type": type_name, "index": value_index, "value": value})

    @staticmethod
    def _to_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def fuzz_payloads(self, strings, numeric_range, policy_types=None, limit=None):
        """Return type-aware mutations of values referenced by RPC parameters."""
        result = []
        seen = set()
        policy_types = set(policy_types or [])
        try:
            columns = int(self.parts[2])
        except (IndexError, TypeError, ValueError):
            return result
        for parameter_number, parameter in enumerate(self.parameters):
            value_index = parameter.get("index")
            part_index = value_index + 2 if value_index is not None else None
            if (part_index is None or value_index <= 4 or value_index > columns or
                    part_index >= len(self.parts)):
                continue
            value_type = parameter.get("type", "")
            original = self.parts[part_index]
            policy_match = value_type in policy_types
            candidates = []
            lowered_type = value_type.lower()
            if any(name in lowered_type for name in ("string", "charsequence")):
                candidates.extend([("empty string", ""), ("null-like string", "null"),
                                   ("malformed value", "!invalid!"), ("long string", "A" * 256)])
            elif "boolean" in lowered_type:
                candidates.extend([("empty value", ""), ("null-like value", "null"),
                                   ("malformed value", "!invalid!"),
                                   ("boolean true", "true"), ("boolean false", "false")])
            elif any(name in lowered_type for name in ("byte", "short", "int", "long")):
                bounds = ("-128", "127") if "byte" in lowered_type else (
                    ("-32768", "32767") if "short" in lowered_type else (
                    ("-2147483648", "2147483647") if "int" in lowered_type else
                    ("-9223372036854775808", "9223372036854775807")))
                candidates.extend([("empty value", ""), ("null-like value", "null"),
                                   ("malformed value", "!invalid!"),
                                   ("minimum boundary", bounds[0]),
                                   ("maximum boundary", bounds[1]), ("zero", "0")])
                number = self._to_int(original)
                if number is not None:
                    for value in range(number - numeric_range, number + numeric_range + 1):
                        candidates.append(("numeric: " + str(value), str(value)))
            elif any(name in lowered_type for name in ("float", "double", "decimal")):
                candidates.extend([("empty value", ""), ("null-like value", "null"),
                                   ("malformed value", "!invalid!"),
                                   ("zero", "0"), ("negative", "-1"),
                                   ("large magnitude", "1e100")])
            else:
                candidates.extend([("empty value", ""), ("null-like value", "null"),
                                   ("malformed value", "!invalid!")])
            for value in strings:
                candidates.append(("custom: " + value, value))
            for label, value in candidates:
                copy = list(self.parts)
                copy[part_index] = value.replace("|", "\\!")
                payload = "|".join(copy)
                key = (part_index, payload)
                if key not in seen and payload != self.payload:
                    seen.add(key)
                    type_label = value_type or "unknown"
                    if policy_match:
                        type_label += ", serialization policy"
                    result.append(("parameter %d (%s): %s" %
                                   (parameter_number + 1, type_label, label), payload))
                    if limit is not None and len(result) >= limit:
                        return result
        return result


class GwtResponse(object):
    """Decode the status envelope used by GWT-RPC responses."""

    @staticmethod
    def decode(payload):
        text = payload or ""
        for marker in ("//OK", "//EX", "//NR"):
            if text.startswith(marker):
                return marker[2:], text[len(marker):]
        return "UNKNOWN", text

    @staticmethod
    def values(payload):
        try:
            decoded = json.loads(payload)
        except (TypeError, ValueError):
            return [("raw", payload)]
        result = []

        def flatten(value, path):
            if isinstance(value, list):
                for index, item in enumerate(value):
                    flatten(item, "%s[%d]" % (path, index))
            elif isinstance(value, dict):
                for key, item in value.items():
                    flatten(item, "%s.%s" % (path, key))
            else:
                result.append((path, value))

        flatten(decoded, "response")
        return result

    @staticmethod
    def compare(left, right):
        left_values = dict((path, str(value)) for path, value in
                           GwtResponse.values(left.get("payload", "")))
        right_values = dict((path, str(value)) for path, value in
                            GwtResponse.values(right.get("payload", "")))
        changed = sorted(path for path in set(left_values) | set(right_values)
                         if left_values.get(path) != right_values.get(path))
        return {"body_changed": left.get("body", "") != right.get("body", ""),
                "changed_paths": changed}


class GwtMessageDecoder(object):
    """Format decoded GWT request and response bodies for Burp message tabs."""

    @staticmethod
    def decode_request(payload):
        parsed = GwtRpc(payload).parse()
        if parsed.error:
            return None
        lines = ["GWT-RPC request", "Host: %s" % parsed.host,
                 "Strong name: %s" % parsed.strong_name,
                 "Interface: %s" % parsed.interface_name,
                 "Method: %s" % parsed.method_name,
                 "Parameters: %d" % len(parsed.parameters)]
        for index, parameter in enumerate(parsed.parameters):
            lines.append("Parameter %d (%s, index %s): %s" %
                         (index + 1, parameter["type"], parameter["index"],
                          parameter["value"]))
        return "\n".join(lines)

    @staticmethod
    def decode_response(payload):
        envelope, response_payload = GwtResponse.decode(payload)
        if envelope == "UNKNOWN":
            return None
        lines = ["GWT-RPC response", "Envelope: %s" % envelope,
                 "Payload: %s" % response_payload]
        for path, value in GwtResponse.values(response_payload):
            lines.append("%s: %s" % (path, value))
        return "\n".join(lines)


class _GwtMessageEditorTab(IMessageEditorTab):
    def __init__(self, helpers):
        self.helpers = helpers
        self.area = JTextArea()
        self.area.setEditable(False)
        self.area.setLineWrap(True)
        self.area.setWrapStyleWord(True)
        self.component = JScrollPane(self.area)

    def getTabCaption(self):
        return "Decoded GWT RPC"

    def getUiComponent(self):
        return self.component

    def isEnabled(self, content, is_request):
        try:
            if is_request:
                info = self.helpers.analyzeRequest(content)
                body = self.helpers.bytesToString(content[info.getBodyOffset():])
                if any(header.lower().startswith("content-type:") and
                       "text/x-gwt-rpc" in header.lower()
                       for header in info.getHeaders()):
                    return True
                return GwtMessageDecoder.decode_request(body) is not None
            info = self.helpers.analyzeResponse(content)
            body = self.helpers.bytesToString(content[info.getBodyOffset():])
            return GwtMessageDecoder.decode_response(body) is not None
        except Exception:
            return False

    def setMessage(self, content, is_request):
        if content is None:
            self.area.setText("")
            return
        if is_request:
            info = self.helpers.analyzeRequest(content)
            body = self.helpers.bytesToString(content[info.getBodyOffset():])
            decoded = GwtMessageDecoder.decode_request(body)
            self.area.setText(decoded or "GWT-RPC request body could not be decoded")
        else:
            info = self.helpers.analyzeResponse(content)
            body = self.helpers.bytesToString(content[info.getBodyOffset():])
            decoded = GwtMessageDecoder.decode_response(body)
            status = info.getStatusCode()
            self.area.setText("HTTP status: %s\n%s" %
                              (status, decoded or "GWT-RPC response could not be decoded"))
        self.area.setCaretPosition(0)

    def getMessage(self):
        return None

    def isModified(self):
        return False

    def getSelectedData(self):
        return None


class GwtResponseFinder(object):
    """Find likely exception details, stack traces, and sensitive response fields."""

    STACK_RE = __import__('re').compile(
        r"(?m)^\s*at\s+[A-Za-z_$][\w.$<>]*\([^\r\n)]*\)"
    )
    EXCEPTION_RE = __import__('re').compile(
        r"\b(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:Exception|Error)\b"
        r"(?:\s*:\s*[^\r\n]{0,180})?"
    )
    DISCLOSURE_RE = __import__('re').compile(
        r"(?i)[\"']?(password|passwd|ssn|social.?security|credit.?card|"
        r"access.?token|refresh.?token)[\"']?\s*[:=]\s*[\"']?"
        r"([^\"'\s,}\]]{1,128})"
    )

    @classmethod
    def find(cls, source):
        text = source or ""
        findings = []
        seen = set()

        def add(kind, evidence, detail):
            key = (kind, evidence)
            if key not in seen:
                seen.add(key)
                findings.append((kind, evidence, detail))

        for match in cls.STACK_RE.finditer(text):
            add("Java stack trace", " ".join(match.group(0).split()),
                "Captured response contains a Java-style stack frame")
        for match in cls.EXCEPTION_RE.finditer(text):
            value = " ".join(match.group(0).split())
            add("Java exception detail", value[:180],
                "Exception or error class found in captured response")
        for match in cls.DISCLOSURE_RE.finditer(text):
            label = match.group(1)
            evidence = label + "=" + GwtSensitiveFinder._mask(match.group(2))
            add("Possible sensitive response field", evidence,
                "Sensitive field name and value shape found; verify business context")
        return findings


class GwtClassFinder(object):
    """Find Java-style fully qualified class names in GWT assets."""

    CLASS_RE = __import__('re').compile(
        r"\b(?:[a-z_$][\w$]*\.)+[A-Z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\b"
    )

    @staticmethod
    def purpose(name):
        lowered = name.lower()
        if "startloadingfragment" in lowered or "installrunasynccode" in lowered:
            return "Loads deferred GWT code"
        if "modulebase" in lowered or "modulename" in lowered or "propmap" in lowered:
            return "Identifies the GWT module or browser properties"
        if "sendstats" in lowered or "stats" in lowered:
            return "Sends application or performance statistics"
        if "style" in lowered or "css" in lowered:
            return "Handles application styling"
        if "err" in lowered or "exception" in lowered:
            return "Handles errors or exceptions"
        if "service" in lowered or "rpc" in lowered:
            return "Related to a GWT-RPC service"
        if "event" in lowered or "session" in lowered:
            return "Handles application events or session state"
        return "Compiled GWT runtime or application symbol"

    @classmethod
    def find(cls, source):
        text = source or ""
        matches = {}
        for match in cls.CLASS_RE.finditer(text):
            name = match.group(0)
            if name in matches:
                continue
            final_part = name.rsplit(".", 1)[-1]
            kind = "Java class" if final_part[:1].isupper() else "GWT symbol"
            context_start = max(0, match.start() - 45)
            context_end = min(len(text), match.end() + 45)
            context = " ".join(text[context_start:context_end].split())
            matches[name] = (kind, context, cls.purpose(name))
        return sorted([(name, details[0], details[1], details[2])
                       for name, details in matches.items()])


class GwtSensitiveFinder(object):
    """Find likely sensitive values and encoding/crypto indicators in assets."""

    SECRET_RE = __import__('re').compile(
        r"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*[\"']([^\"']{8,})[\"']"
    )
    EMAIL_RE = __import__('re').compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )
    JWT_RE = __import__('re').compile(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    )
    PRIVATE_KEY_RE = __import__('re').compile(
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----"
    )
    BASE64_RE = __import__('re').compile(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])"
    )
    METHOD_RE = __import__('re').compile(
        r"(?i)\b(atob|btoa|decodeURIComponent|encodeURIComponent|fromCharCode|CryptoJS|SubtleCrypto|AES|DES|RSA|encrypt|decrypt|base64|hex)\b"
    )

    @staticmethod
    def _mask(value):
        if len(value) <= 10:
            return "[masked]"
        return value[:4] + "..." + value[-4:]

    @classmethod
    def find(cls, source):
        text = source or ""
        findings = []
        seen = set()

        def add(kind, evidence, method, details):
            key = (kind, evidence, method, details)
            if key not in seen:
                seen.add(key)
                findings.append((kind, evidence, method, details))

        for match in cls.SECRET_RE.finditer(text):
            label = match.group(0).split("=", 1)[0].split(":", 1)[0].strip()
            add("Possible secret: " + label, match.group(1), "Hard-coded value",
                "Full matched value; verify whether it is active")
        for match in cls.PRIVATE_KEY_RE.finditer(text):
            add("Private key", match.group(0), "PEM key marker", "Private-key header detected")
        for match in cls.JWT_RE.finditer(text):
            add("JWT token", match.group(0), "JSON Web Token", "JWT-shaped token detected")
        for match in cls.EMAIL_RE.finditer(text):
            add("Email address", match.group(0), "Email pattern", "Email-shaped value detected")
        for match in cls.BASE64_RE.finditer(text):
            add("Possible Base64", match.group(0), "Base64-shaped value",
                "Full candidate value; pattern alone does not prove Base64")
        for match in cls.METHOD_RE.finditer(text):
            add("Encoding/crypto indicator", match.group(1), "Detected API or method",
                "Function or library name suggests encoding or cryptography")
        return findings


class GwtSupportFileFinder(object):
    """Extract serialization policies and symbol-map/deobfuscation entries."""

    TYPE_RE = __import__('re').compile(
        r"\b(?:[a-z_$][\w$]*\.)+[A-Z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\b"
    )
    SOURCE_MAP_RE = __import__('re').compile(
        r"sourceMappingURL\s*=\s*([^\s*]+)"
    )

    @classmethod
    def policy_types(cls, source):
        return sorted(set(cls.TYPE_RE.findall(source or "")))

    @classmethod
    def symbol_entries(cls, source):
        entries = []
        for line in (source or "").splitlines():
            parts = [part.strip() for part in line.split(",")]
            if len(parts) >= 2 and parts[0] and parts[1]:
                entries.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))
        try:
            source_map = json.loads(source or "")
            sources = source_map.get("sources", [])
            names = source_map.get("names", [])
            for name in names:
                entries.append((name, name, "source map name"))
            for source_name in sources:
                entries.append((source_name, source_name, "source map source"))
        except (TypeError, ValueError, AttributeError):
            pass
        return entries

    @classmethod
    def source_map_reference(cls, source):
        match = cls.SOURCE_MAP_RE.search(source or "")
        return match.group(1) if match else ""


class GwtMap(object):
    """Regex-based mapper for bootstrap/permutation JavaScript."""

    SERVICE_RE = __import__('re').compile(
        r"(?:call\([^,]+,\s*)['\"]?([^,'\"]+)['\"]?\s*,\s*['\"]?([A-Z0-9]{20,40})"
    )
    METHOD_RE = __import__('re').compile(
        r"(?:new\s+)?[A-Za-z0-9_$]+\s*=\s*new\s+[A-Za-z0-9_$]+\([^,]+,\s*['\"]?([^,'\"]+)['\"]?"
    )
    HASH_RE = __import__('re').compile(r"[A-Z0-9]{30,35}")

    @staticmethod
    def fetch(callbacks, helpers, target):
        status, _, _, source = GwtMap.fetch_exchange(callbacks, helpers, target)
        return status, source

    @staticmethod
    def fetch_exchange(callbacks, helpers, target):
        target_url = URL(target)
        request = helpers.buildHttpRequest(target_url)
        service = helpers.buildHttpService(target_url.getHost(), target_url.getPort(),
                                           target_url.getProtocol().lower() == "https")
        request_text = helpers.bytesToString(request)
        response = callbacks.makeHttpRequest(service, request)
        raw = response.getResponse() if response is not None else None
        if raw is None:
            return None, request_text, "", None
        info = helpers.analyzeResponse(raw)
        response_text = helpers.bytesToString(raw)
        source = helpers.bytesToString(raw[info.getBodyOffset():])
        return info.getStatusCode(), request_text, response_text, source

    @classmethod
    def fetch_application(cls, callbacks, helpers, target):
        """Fetch a bootstrap, its selected permutation, and deferred fragments."""
        status, bootstrap = cls.fetch(callbacks, helpers, target)
        if status != 200 or bootstrap is None:
            return status, bootstrap, target
        hashes = cls.HASH_RE.findall(bootstrap)
        if not hashes:
            return status, bootstrap, target
        base = target.rsplit('/', 1)[0] + '/'
        permutation = base + hashes[0] + ".cache.js"
        perm_status, code = cls.fetch(callbacks, helpers, permutation)
        if perm_status != 200 or code is None:
            return perm_status, bootstrap, permutation
        combined = code
        for index in range(10):
            fragment = base + "deferredjs/" + hashes[0] + "/" + str(index) + ".cache.js"
            frag_status, fragment_code = cls.fetch(callbacks, helpers, fragment)
            if frag_status != 200 or not fragment_code:
                break
            combined += "\n" + fragment_code
        return perm_status, combined, permutation

    @classmethod
    def analyze(cls, code):
        text = code or ""
        services = []
        for match in cls.SERVICE_RE.finditer(text):
            item = {"path": match.group(1), "strong_name": match.group(2)}
            if item not in services:
                services.append(item)
        methods = []
        for match in cls.METHOD_RE.finditer(text):
            name = match.group(1)
            if name not in methods and not name.isupper():
                methods.append(name)
        hashes = []
        for value in cls.HASH_RE.findall(text):
            if value not in hashes:
                hashes.append(value)
        return services, methods, hashes

    @classmethod
    def no_argument_rpc(cls, base_url, service, method):
        """Build the valid baseline RPC body for a method with no arguments."""
        strong_name = service.get("strong_name", "X" * 32)
        interface_name = service.get("interface", "")
        return "|".join(["7", "0", "7", base_url, strong_name,
                          interface_name, method, "1", "2", "3", "4", "0", ""])


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener, IMessageEditorTabFactory,
                   IMessageEditorController, IProxyListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.loaded_request = None
        self.loaded_service = None
        self.editor_http_service = None
        self.editor_request_message = None
        self.editor_response_message = None
        self.history_messages = []
        self.history_keys = set()
        self.history_rows = {}
        self.asset_keys = set()
        self.asset_messages = []
        self.asset_rows = {}
        self.class_keys = set()
        self.sensitive_keys = set()
        self.policy_keys = set()
        self.symbol_keys = set()
        self.symbol_mappings = {}
        self.support_sources = {}
        self.map_fetch_keys = set()
        self.source_map_fetches = []
        self.source_map_fetch_rows = {}
        self.integrity_candidates = []
        self.integrity_request = None
        self.integrity_service = None
        self.passive_response_keys = set()
        self.alternate_auth_headers = {}
        self.alternate_auth_source = ""
        self.fuzz_running = AtomicBoolean(False)
        self.stop_fuzz = AtomicBoolean(False)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("GWT RPC Toolkit")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)
        callbacks.registerMessageEditorTabFactory(self)
        self._build_ui()
        callbacks.addSuiteTab(self)
        SwingUtilities.invokeLater(_UiUpdate(self.load_history))
        self.stdout.println("GWT RPC Toolkit loaded")

    def createNewInstance(self, controller, editable):
        return _GwtMessageEditorTab(self.helpers)

    def getHttpService(self):
        return self.editor_http_service

    def getRequest(self):
        return self.editor_request_message

    def getResponse(self):
        return self.editor_response_message

    def _set_request_message(self, message):
        raw = self._message_bytes(message)
        self.editor_request_message = raw
        self.request_editor.setMessage(raw, True)
        self.request_area.setText(self._message_text(raw))

    def _set_response_message(self, message):
        raw = self._message_bytes(message)
        self.editor_response_message = raw
        self.response_editor.setMessage(raw, False)
        self.response_area.setText(self._message_text(raw))

    def _message_bytes(self, message):
        if message is None:
            return None
        if isinstance(message, basestring):
            return self.helpers.stringToBytes(message)
        return message

    def _message_text(self, message):
        return self.helpers.bytesToString(message) if message is not None else ""

    def _build_ui(self):
        self.input_area = JTextArea(12, 80)
        self.request_area = JTextArea(12, 80)
        self.response_area = JTextArea(12, 80)
        self.request_editor = self.callbacks.createMessageEditor(self, False)
        self.response_editor = self.callbacks.createMessageEditor(self, False)
        self.output_area = JTextArea(18, 80)
        self.input_area.setLineWrap(True)
        self.input_area.setWrapStyleWord(True)
        self.request_area.setLineWrap(True)
        self.request_area.setWrapStyleWord(True)
        self.response_area.setLineWrap(True)
        self.response_area.setWrapStyleWord(True)
        self.request_area.setEditable(False)
        self.response_area.setEditable(False)
        self._style_message_area(self.input_area, Color(24, 69, 112))
        self._style_message_area(self.request_area, Color(24, 69, 112))
        self._style_message_area(self.response_area, Color(27, 92, 55))
        self.output_area.setLineWrap(True)
        self.output_area.setWrapStyleWord(True)
        self.output_area.setEditable(False)
        self.strings_area = JTextArea("test\n'\"><script>alert(1)</script>\nnull", 4, 40)
        self.range_spinner = JSpinner(SpinnerNumberModel(5, 1, 1000, 1))
        self.auto_check = JCheckBox("Capture GWT requests", True)
        self.findings_model = DefaultTableModel(["Type", "Name", "Details"], 0)
        self.decoded_model = DefaultTableModel(["Part", "Type", "Index", "Value", "Details"], 0)
        self.activity_model = DefaultTableModel(["Action", "Result"], 0)
        self.history_model = DefaultTableModel(["#", "Method", "URL", "Type", "Status"], 0)
        self.asset_model = DefaultTableModel(["Asset", "URL", "Status"], 0)
        self.class_model = DefaultTableModel(["Class / Symbol", "Kind", "Likely Work", "Details", "Source URL"], 0)
        self.sensitive_model = DefaultTableModel(["Category", "Evidence", "Method", "Details", "Source URL"], 0)
        self.policy_model = DefaultTableModel(["Serialized Java Type", "Policy URL"], 0)
        self.symbol_model = DefaultTableModel(["Obfuscated", "Original", "Source", "Map URL"], 0)
        self.integrity_model = DefaultTableModel(["Location", "Kind", "Evidence"], 0)
        self.source_map_fetch_model = DefaultTableModel(["Source Map URL", "Status", "Response size"], 0)
        self.findings_table = JTable(self.findings_model)
        self.decoded_table = JTable(self.decoded_model)
        decoded_renderer = _DecodedCellRenderer()
        for column_index in range(self.decoded_model.getColumnCount()):
            self.decoded_table.getColumnModel().getColumn(column_index).setCellRenderer(decoded_renderer)
        self.activity_table = JTable(self.activity_model)
        self.history_table = JTable(self.history_model)
        self.asset_table = JTable(self.asset_model)
        self.class_table = JTable(self.class_model)
        self.sensitive_table = JTable(self.sensitive_model)
        self.policy_table = JTable(self.policy_model)
        self.symbol_table = JTable(self.symbol_model)
        self.integrity_table = JTable(self.integrity_model)
        self.source_map_fetch_table = JTable(self.source_map_fetch_model)
        self.source_map_request_area = JTextArea(12, 60)
        self.source_map_response_area = JTextArea(12, 60)
        self.source_map_request_area.setEditable(False)
        self.source_map_response_area.setEditable(False)
        for table in (self.findings_table, self.decoded_table, self.activity_table,
                      self.history_table, self.asset_table, self.class_table,
                  self.sensitive_table, self.policy_table, self.symbol_table,
                  self.integrity_table, self.source_map_fetch_table):
            table.setAutoCreateRowSorter(True)
        history_sorter = self.history_table.getRowSorter()
        history_sorter.setComparator(0, _NumericComparator())
        history_sorter.setComparator(4, _NumericComparator())
        self.symbol_search = JTextField()
        self.symbol_lookup_output = JTextArea(6, 80)
        self.symbol_stack_input = JTextArea(8, 80)
        self.symbol_stack_output = JTextArea(8, 80)
        self.symbol_lookup_output.setEditable(False)
        self.symbol_stack_output.setEditable(False)
        self.asset_table.getSelectionModel().addListSelectionListener(
            _Selection(lambda: self._select_asset_row(self.asset_table)))
        self.history_table.getSelectionModel().addListSelectionListener(
            _Selection(lambda: self._select_history_row(self.history_table)))
        self.sensitive_table.getSelectionModel().addListSelectionListener(
            _Selection(lambda: self._select_source_row(self.sensitive_table, 1, 4)))
        self.class_table.getSelectionModel().addListSelectionListener(
            _Selection(lambda: self._select_source_row(self.class_table, 0, 4)))
        self.policy_table.getSelectionModel().addListSelectionListener(
            _Selection(lambda: self._select_source_row(self.policy_table, 0, 1)))
        self.symbol_table.getSelectionModel().addListSelectionListener(
            _Selection(lambda: self._select_source_row(self.symbol_table, 0, 3, 1)))
        self.integrity_table.getSelectionModel().addListSelectionListener(
            _Selection(self._select_integrity_row))
        self.source_map_fetch_table.getSelectionModel().addListSelectionListener(
            _Selection(self._select_source_map_fetch))

        buttons = JPanel(GridLayout(2, 0))
        self._button(buttons, "Parse RPC", self.parse_rpc)
        self._button(buttons, "Map JavaScript", self.map_javascript)
        self._button(buttons, "Fuzz Through Burp", self.fuzz_request)
        self._button(buttons, "Preview Fuzz Count", self.preview_fuzz_count)
        self.stop_button = JButton("Stop Fuzz")
        self.stop_button.setEnabled(False)
        self.stop_button.addActionListener(_Action(self.stop_fuzzing))
        buttons.add(self.stop_button)
        self._button(buttons, "Load GWT History", self.load_history)
        self._button(buttons, "Decode Selected", self.decode_selected_history)
        self._button(buttons, "Set Alt Session", self.set_alternate_session)
        self._button(buttons, "Compare Session", self.compare_alternate_session)
        self._button(buttons, "Find Tokens", self.find_integrity_tokens)
        self._button(buttons, "Probe Token", self.probe_integrity_token)
        self._button(buttons, "Clear", self.clear_output)

        controls = JPanel(BorderLayout())
        self.message_tabs = JTabbedPane()
        self.message_tabs.addTab(
            "Payload / JavaScript",
            self._with_tab_intro("Enter an RPC body, JavaScript source, or a GWT bootstrap URL.",
                                 self._wrapped_scroll(self.input_area)))
        request_panel = JPanel(BorderLayout())
        request_panel.add(JLabel("Request"), BorderLayout.NORTH)
        request_panel.add(self.request_editor.getComponent(), BorderLayout.CENTER)
        response_panel = JPanel(BorderLayout())
        response_panel.add(JLabel("Response"), BorderLayout.NORTH)
        response_panel.add(self.response_editor.getComponent(), BorderLayout.CENTER)
        request_response_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                            request_panel, response_panel)
        request_response_split.setResizeWeight(0.5)
        request_response_split.setOneTouchExpandable(True)
        request_response_split.setContinuousLayout(True)
        self.message_tabs.addTab(
            "Request / Response",
            self._with_tab_intro(
                "Compare the captured HTTP request on the left with its response on the right.",
                request_response_split))
        controls.add(self.message_tabs, BorderLayout.CENTER)
        controls.add(buttons, BorderLayout.SOUTH)

        options = JPanel(GridLayout(5, 2))
        self.max_requests_spinner = JSpinner(SpinnerNumberModel(100, 1, 10000, 10))
        self.delay_spinner = JSpinner(SpinnerNumberModel(100, 0, 60000, 50))
        self.active_check = JCheckBox("Allow active replay / mutation", False)
        self.fuzz_count_label = JLabel("Fuzz requests: preview required")
        options.add(JLabel("String payloads (one per line):"))
        options.add(JLabel("Numeric radius:"))
        options.add(JScrollPane(self.strings_area))
        options.add(self.range_spinner)
        options.add(JLabel("Maximum requests / delay (ms):"))
        options.add(JLabel(""))
        options.add(self.max_requests_spinner)
        options.add(self.delay_spinner)
        options.add(self.active_check)
        options.add(self.fuzz_count_label)

        self.result_tabs = JTabbedPane()
        self.result_tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)
        output_scroll = JScrollPane(self.output_area)
        output_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        self.result_tabs.addTab(
            "Activity", self._with_tab_intro(
                "Review extension actions, request outcomes, and replay status.", output_scroll))
        self.result_tabs.addTab(
            "Findings", self._with_tab_intro(
                "Review detected RPC methods, mappings, and passive response findings.",
                JScrollPane(self.findings_table)))
        self.result_tabs.addTab(
            "Decoded", self._with_tab_intro(
                "Inspect parsed RPC fields and decoded response values.",
                JScrollPane(self.decoded_table)))
        self.result_tabs.addTab(
            "History", self._with_tab_intro(
                "Browse captured requests and select one to inspect its messages.",
                JScrollPane(self.history_table)))
        self.result_tabs.addTab(
            "GWT Assets", self._with_tab_intro(
                "Browse observed GWT bootstrap and permutation JavaScript assets.",
                JScrollPane(self.asset_table)))
        self.result_tabs.addTab(
            "Classes", self._with_tab_intro(
                "Review Java-style classes and symbols found in captured assets.",
                JScrollPane(self.class_table)))
        self.result_tabs.addTab(
            "Sensitive Data", self._with_tab_intro(
                "Review heuristic matches for secrets, tokens, keys, and related patterns.",
                JScrollPane(self.sensitive_table)))
        self.result_tabs.addTab(
            "Serialization Policies", self._with_tab_intro(
                "Browse Java types extracted from observed GWT serialization policies.",
                JScrollPane(self.policy_table)))
        self.result_tabs.addTab(
            "Symbol Maps", self._with_tab_intro(
                "Browse deobfuscation entries and source-map references.",
                JScrollPane(self.symbol_table)))
        self.result_tabs.addTab(
            "Source Map Traffic", self._with_tab_intro(
                "Inspect HTTP requests and responses for automatically fetched source maps.",
                self._build_source_map_traffic_tab()))
        self.result_tabs.addTab(
            "Integrity Checks", self._with_tab_intro(
                "Review token candidates detected in captured requests.",
                JScrollPane(self.integrity_table)))
        symbol_tools_builder = getattr(self, "_build_symbol_tools", None)
        if symbol_tools_builder is not None:
            self.result_tabs.addTab(
                "Symbol Tools", self._with_tab_intro(
                    "Search mappings, deobfuscate stack traces, and manage symbol maps.",
                    symbol_tools_builder()))
        self.result_tabs.addTab(
            "Wiki", self._with_tab_intro(
                "Read the usage guide and reference for this extension.",
                self._build_wiki_tab()))
        for tab_index in range(self.result_tabs.getTabCount()):
            self.result_tabs.setTabComponentAt(
                tab_index, _ExpandedTabLabel(
                    self.result_tabs, tab_index, self.result_tabs.getTitleAt(tab_index)))

        message_results_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.result_tabs, controls)
        message_results_split.setResizeWeight(0.4)
        message_results_split.setOneTouchExpandable(True)
        message_results_split.setContinuousLayout(True)

        root_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, message_results_split, options)
        root_split.setResizeWeight(0.86)
        root_split.setOneTouchExpandable(True)
        root_split.setContinuousLayout(True)

        root = JPanel(BorderLayout())
        root.add(root_split, BorderLayout.CENTER)
        self.panel = root

    @staticmethod
    def _wrapped_scroll(area):
        scroll = JScrollPane(area)
        scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        return scroll

    def _with_tab_intro(self, description, content):
        panel = JPanel(BorderLayout())
        header = JPanel(BorderLayout())
        help_button = JButton("?")
        help_button.setToolTipText("Open the extension Wiki")
        help_button.setBorderPainted(False)
        help_button.setContentAreaFilled(False)
        help_button.setFocusable(False)
        help_button.addActionListener(_Action(self._open_wiki))
        header.add(help_button, BorderLayout.WEST)
        header.add(JLabel(description), BorderLayout.CENTER)
        panel.add(header, BorderLayout.NORTH)
        panel.add(content, BorderLayout.CENTER)
        return panel

    def _open_wiki(self):
        wiki_index = self.result_tabs.indexOfTab("Wiki")
        if wiki_index >= 0:
            self.result_tabs.setSelectedIndex(wiki_index)

    @staticmethod
    def _style_message_area(area, background):
        area.setBackground(background)
        area.setForeground(Color.WHITE)
        area.setCaretColor(Color.WHITE)
        area.setFont(Font("Monospaced", Font.PLAIN, 14))
        area.setOpaque(True)

    def _build_symbol_tools(self):
        panel = JPanel(BorderLayout())
        search_panel = JPanel(BorderLayout())
        search_panel.add(JLabel("Obfuscated name:"), BorderLayout.WEST)
        search_panel.add(self.symbol_search, BorderLayout.CENTER)
        lookup_button = JButton("Lookup")
        lookup_button.addActionListener(_Action(self.lookup_symbol))
        search_panel.add(lookup_button, BorderLayout.EAST)

        stack_panel = JPanel(GridLayout(1, 2))
        stack_panel.add(JScrollPane(self.symbol_stack_input))
        stack_panel.add(JScrollPane(self.symbol_stack_output))

        actions = JPanel(GridLayout(1, 0))
        self._button(actions, "Deobfuscate Stack", self.deobfuscate_stack)
        self._button(actions, "Upload Symbol Map", self.upload_symbol_map)
        self._button(actions, "Export CSV", lambda: self.export_mappings("csv"))
        self._button(actions, "Export JSON", lambda: self.export_mappings("json"))

        bottom = JPanel(GridLayout(2, 1))
        bottom.add(stack_panel)
        bottom.add(actions)
        panel.add(search_panel, BorderLayout.NORTH)
        panel.add(JScrollPane(self.symbol_lookup_output), BorderLayout.CENTER)
        panel.add(bottom, BorderLayout.SOUTH)
        return panel

    def _build_wiki_tab(self):
        left_guide = JTextArea(24, 45)
        right_guide = JTextArea(24, 45)
        for guide in (left_guide, right_guide):
            guide.setEditable(False)
            guide.setLineWrap(True)
            guide.setWrapStyleWord(True)

        left_guide.setText("""GWT RPC EXTENSION - QUICK GUIDE

QUICK START
1. In Burp Proxy or HTTP history, right-click a GWT request and choose
   Send to GWT RPC Toolkit.
2. In Payload / JavaScript, review the request body and click Parse RPC.
3. For fuzzing, set payloads and limits, enable Allow active replay / mutation,
   preview the request count, then click Fuzz Through Burp.
4. Review responses and findings in the result tabs below.

OTHER WORKFLOWS
Map JavaScript: Paste a .nocache.js URL or captured JavaScript, then click
  Map JavaScript to inspect service and method candidates.
Compare Session: Select an alternate-account request, click Set Alt Session,
  load the baseline request, enable active replay, then click Compare Session.
Decoded GWT RPC: In Burp request/response editors, open this read-only tab to
  inspect a decoded GWT message.

SAFETY
Replay, fuzzing, comparison, and integrity probes send requests and may cause
application-side effects. Use only with authorization. Keep the request cap low
and the delay appropriate for the test environment.""")

        right_guide.setText("""TAB GUIDE

INPUT TABS
Payload / JavaScript: Paste a GWT-RPC body to parse or fuzz, or JavaScript or a
bootstrap URL to map an application.
Request: Inspect the loaded full HTTP request. This view is read-only.
Response: Inspect the associated HTTP response when one is available. Read-only.

RESULT TABS
Activity: Action messages, fuzz results, and replay status.
Findings: RPC methods, mapping results, and passive response findings. Verify
  heuristic results in their application context.
Decoded: Parsed RPC fields and decoded response values for a history entry.
History: Browse captured requests. Select one to load it, or use Decode Selected.
GWT Assets: Observed .nocache.js and .cache.js resources; select one to inspect it.
Classes: Java-style names detected in GWT JavaScript, with context and source URL.
    Select a row to open its source response and highlight the class name.
Sensitive Data: Heuristic matches for secrets, tokens, keys, and related patterns.
    Select a row to open its source response and highlight the evidence.
Serialization Policies: Java types extracted from observed .gwt.rpc policy files.
    Select a type to open its policy response and highlight the type name.
Symbol Maps: Entries and source-map references found in observed map assets.
    Select an entry to open its source and highlight the matching symbol.
Source Map Traffic: Review automatically fetched source-map URLs and HTTP
    status. Each completed fetch displays its exact HTTP request and raw response;
    select another row to revisit a previous fetch.
Integrity Checks: Token candidates from Find Tokens. Select a row to open the
    scanned request and highlight the candidate field or value. Use Probe Token
    only after selecting a candidate.
Symbol Tools: Search or upload symbol maps, deobfuscate pasted text, and export
  loaded mappings as CSV or JSON.
Wiki: This usage guide.

All results are heuristic where noted. Confirm findings against authorized
application behavior and the relevant captured request or asset.""")

        left_guide.setCaretPosition(0)
        right_guide.setCaretPosition(0)
        wiki_panel = JPanel(GridLayout(1, 2, 8, 0))
        wiki_panel.add(JScrollPane(left_guide))
        wiki_panel.add(JScrollPane(right_guide))
        return wiki_panel

    def _build_source_map_traffic_tab(self):
        request_panel = JPanel(BorderLayout())
        request_panel.add(JLabel("HTTP Request"), BorderLayout.NORTH)
        request_panel.add(JScrollPane(self.source_map_request_area), BorderLayout.CENTER)
        response_panel = JPanel(BorderLayout())
        response_panel.add(JLabel("HTTP Response"), BorderLayout.NORTH)
        response_panel.add(JScrollPane(self.source_map_response_area), BorderLayout.CENTER)
        exchange_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                    request_panel, response_panel)
        exchange_split.setResizeWeight(0.5)
        tab_split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                               JScrollPane(self.source_map_fetch_table), exchange_split)
        tab_split.setResizeWeight(0.3)
        tab_split.setContinuousLayout(True)
        return tab_split

    def _add_symbol_entry(self, obfuscated, original, source_name, map_url):
        if not obfuscated or not original:
            return
        key = "%s\n%s\n%s\n%s" % (obfuscated, original, source_name, map_url)
        if key in self.symbol_keys:
            return
        self.symbol_keys.add(key)
        self.symbol_mappings[obfuscated] = original
        self.symbol_model.addRow([obfuscated, original, source_name, map_url])

    def _add_symbol_entries(self, entries, map_url):
        for obfuscated, original, source_name in entries:
            self._add_symbol_entry(obfuscated, original, source_name, map_url)

    def lookup_symbol(self):
        query = self.symbol_search.getText().strip().lower()
        matches = []
        for obfuscated, original in self.symbol_mappings.items():
            if not query or query in obfuscated.lower() or query in original.lower():
                matches.append("%s -> %s" % (obfuscated, original))
        self.symbol_lookup_output.setText("\n".join(sorted(matches)) or "No mapping found")

    def deobfuscate_stack(self):
        text = self.symbol_stack_input.getText()
        for obfuscated in sorted(self.symbol_mappings, key=len, reverse=True):
            text = text.replace(obfuscated, self.symbol_mappings[obfuscated])
        self.symbol_stack_output.setText(text)

    def upload_symbol_map(self):
        chooser = JFileChooser()
        chooser.setFileFilter(FileNameExtensionFilter("Symbol maps (*.symbolMap, *.map, *.json)",
                                                      ["symbolMap", "map", "json"]))
        if chooser.showOpenDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return
        file_path = str(chooser.getSelectedFile().getAbsolutePath())
        try:
            with open(file_path, "r") as source_file:
                source = source_file.read()
            self._add_symbol_entries(GwtSupportFileFinder.symbol_entries(source), file_path)
            self._record("Upload symbol map", file_path)
        except Exception as error:
            self._record("Upload symbol map", "Error: %s" % error)

    def export_mappings(self, format_name):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("gwt-symbol-mappings." + format_name))
        if chooser.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return
        file_path = str(chooser.getSelectedFile().getAbsolutePath())
        try:
            writer = FileWriter(file_path)
            if format_name == "json":
                writer.write(json.dumps(self.symbol_mappings, indent=2, sort_keys=True))
            else:
                writer.write("obfuscated,original\n")
                for obfuscated in sorted(self.symbol_mappings):
                    writer.write('"%s","%s"\n' %
                                 (obfuscated.replace('"', '""'),
                                  self.symbol_mappings[obfuscated].replace('"', '""')))
            writer.close()
            self._record("Export mappings", file_path)
        except Exception as error:
            self._record("Export mappings", "Error: %s" % error)

    def _record(self, action, result):
        self.activity_model.addRow([action, result])
        self.output_area.append("%s: %s\n" % (action, result))

    def _button(self, panel, label, function):
        button = JButton(label)
        button.addActionListener(_Action(function))
        panel.add(button)

    def getTabCaption(self):
        return "GWT RPC"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        item = JMenuItem("Send to GWT RPC Toolkit")
        item.addActionListener(_Action(lambda: self._load_invocation(invocation)))
        return [item]

    def _load_invocation(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages:
            self.loaded_request = messages[0].getRequest()
            self.loaded_service = messages[0].getHttpService()
            self.editor_http_service = self.loaded_service
            request = self.loaded_request
            info = self.helpers.analyzeRequest(request)
            body = request[info.getBodyOffset():]
            self.input_area.setText(self.helpers.bytesToString(body))
            self._set_request_message(request)
            self._set_response_message(None)
            self._record("Loaded request", str(info.getUrl()))

    def load_history(self):
        """Load all requests currently saved in Burp Proxy history."""
        self.history_model.setRowCount(0)
        self.history_messages = []
        self.history_keys = set()
        self.history_rows = {}
        self.asset_model.setRowCount(0)
        self.asset_keys = set()
        self.asset_messages = []
        self.asset_rows = {}
        self.class_model.setRowCount(0)
        self.class_keys = set()
        self.sensitive_model.setRowCount(0)
        self.sensitive_keys = set()
        self.policy_model.setRowCount(0)
        self.policy_keys = set()
        self.symbol_model.setRowCount(0)
        self.symbol_keys = set()
        self.symbol_mappings = {}
        self.support_sources = {}
        self.map_fetch_keys = set()
        self.source_map_fetch_model.setRowCount(0)
        self.source_map_fetches = []
        self.source_map_fetch_rows = {}
        self.integrity_candidates = []
        self.integrity_request = None
        self.integrity_service = None
        try:
            history = self.callbacks.getProxyHistory()
            for message in history:
                try:
                    self._append_history_message(message)
                except Exception as error:
                    self.callbacks.printError("History entry error: %s" % error)
            if not self.history_messages:
                for message in self.callbacks.getSiteMap(None):
                    try:
                        self._append_history_message(message)
                    except Exception as error:
                        self.callbacks.printError("Site map entry error: %s" % error)
        except Exception as error:
            self._record("Load history", "Burp API error: %s" % error)
            return
        self._record("Load history", "%d request(s)" % len(self.history_messages))

    def _append_history_message(self, message):
        """Add one Burp history entry to the History table."""
        request = message.getRequest()
        if request is None:
            return
        service = message.getHttpService()
        if service is None:
            info = self.helpers.analyzeRequest(request)
        else:
            info = self.helpers.analyzeRequest(service, request)
        self._append_asset_message(message, info)
        self._append_support_file(message, info)
        headers = info.getHeaders()
        is_gwt = any(header.lower().startswith("content-type:") and
                     "text/x-gwt-rpc" in header.lower() for header in headers)
        if is_gwt:
            self._append_gwt_response_findings(message, info)
        key = str(info.getUrl()) + "\n" + self.helpers.bytesToString(request)
        if key in self.history_keys:
            response = message.getResponse()
            if response is not None and key in self.history_rows:
                response_info = self.helpers.analyzeResponse(response)
                row_number = self.history_rows[key]
                self.history_messages[row_number] = message
                self.history_model.setValueAt(str(response_info.getStatusCode()), row_number, 4)
            return
        response = message.getResponse()
        status = "-"
        if response is not None:
            response_info = self.helpers.analyzeResponse(response)
            status = str(response_info.getStatusCode())
        row_number = len(self.history_messages)
        self.history_keys.add(key)
        self.history_rows[key] = row_number
        self.history_messages.append(message)
        request_type = "GWT-RPC" if is_gwt else "Other"
        self.history_model.addRow([row_number, info.getMethod(), str(info.getUrl()),
                                   request_type, status])

    def _append_gwt_response_findings(self, message, request_info):
        response = message.getResponse()
        if response is None:
            return
        response_info = self.helpers.analyzeResponse(response)
        body = self.helpers.bytesToString(response[response_info.getBodyOffset():])
        url = str(request_info.getUrl())
        for kind, evidence, detail in GwtResponseFinder.find(body):
            key = (url, kind, evidence)
            if key in self.passive_response_keys:
                continue
            self.passive_response_keys.add(key)
            self.findings_model.addRow([kind, evidence, "%s | %s" % (url, detail)])

    def _append_asset_message(self, message, info):
        url = str(info.getUrl())
        path = url.split("?", 1)[0].lower()
        if not (path.endswith(".nocache.js") or path.endswith(".cache.js")):
            return
        key = url + "\n" + info.getMethod()
        response = message.getResponse()
        status = "-"
        if response is not None:
            status = str(self.helpers.analyzeResponse(response).getStatusCode())
        if key in self.asset_keys:
            row_number = self.asset_rows[key]
            if response is not None:
                self.asset_messages[row_number] = message
                self.asset_model.setValueAt(status, row_number, 2)
        else:
            asset_type = "Bootstrap (.nocache.js)" if path.endswith(".nocache.js") else "Permutation (.cache.js)"
            row_number = len(self.asset_messages)
            self.asset_keys.add(key)
            self.asset_rows[key] = row_number
            self.asset_messages.append(message)
            self.asset_model.addRow([asset_type, url, status])
        if response is None:
            return
        response_info = self.helpers.analyzeResponse(response)
        response_body = response[response_info.getBodyOffset():]
        source = self.helpers.bytesToString(response_body)
        for class_name, kind, details, purpose in GwtClassFinder.find(source):
            class_key = class_name + "\n" + url
            if class_key not in self.class_keys:
                self.class_keys.add(class_key)
                self.class_model.addRow([class_name, kind, purpose, details, url])
        for category, evidence, method, details in GwtSensitiveFinder.find(source):
            finding_key = category + "\n" + evidence + "\n" + url
            if finding_key not in self.sensitive_keys:
                self.sensitive_keys.add(finding_key)
                self.sensitive_model.addRow([category, evidence, method, details, url])

    def _append_support_file(self, message, info):
        response = message.getResponse()
        if response is None:
            return
        response_info = self.helpers.analyzeResponse(response)
        source = self.helpers.bytesToString(response[response_info.getBodyOffset():])
        url = str(info.getUrl())
        path = url.split("?", 1)[0].lower()
        is_policy_file = path.endswith(".gwt.rpc")
        is_symbol_map = (path.endswith(".symbolmap") or path.endswith(".js.map") or
                         path.endswith(".map"))
        reference = GwtSupportFileFinder.source_map_reference(source)
        if is_policy_file or is_symbol_map or reference:
            self.support_sources[url] = source

        if is_policy_file:
            types = GwtSupportFileFinder.policy_types(source)
            if not types:
                types = ["No fully qualified types detected"]
            for type_name in types:
                key = type_name + "\n" + url
                if key not in self.policy_keys:
                    self.policy_keys.add(key)
                    self.policy_model.addRow([type_name, url])

        if is_symbol_map:
            entries = GwtSupportFileFinder.symbol_entries(source)
            if not entries:
                entries = [("", "No symbol entries detected", "")]
            self._add_symbol_entries(entries, url)
        elif reference:
            self._add_symbol_entry("sourceMappingURL", reference, "Referenced by asset", url)
            try:
                map_url = str(URL(URL(url), reference))
                if map_url not in self.map_fetch_keys:
                    self.map_fetch_keys.add(map_url)
                    Thread(_BackgroundTask(lambda: self._fetch_symbol_map(map_url))).start()
            except Exception as error:
                self.callbacks.printError("Symbol map URL error: %s" % error)

    def _fetch_symbol_map(self, map_url):
        request_text = ""
        response_text = ""
        source = None
        entries = []
        try:
            status, request_text, response_text, source = GwtMap.fetch_exchange(
                self.callbacks, self.helpers, map_url)
            if status == 200 and source is not None:
                entries = GwtSupportFileFinder.symbol_entries(source)
        except Exception as error:
            status = "Error: %s" % error
            self.callbacks.printError("Symbol map download error: %s" % error)
        SwingUtilities.invokeLater(_UiUpdate(lambda: self._record_source_map_fetch(
            map_url, status, request_text, response_text, source, entries)))

    def _record_source_map_fetch(self, map_url, status, request_text,
                                 response_text, source, entries):
        record = {"url": map_url, "status": status, "request": request_text,
                  "response": response_text, "source": source}
        row = self.source_map_fetch_rows.get(map_url)
        if row is None:
            row = len(self.source_map_fetches)
            self.source_map_fetch_rows[map_url] = row
            self.source_map_fetches.append(record)
            self.source_map_fetch_model.addRow(
                [map_url, str(status or "No response"), str(len(response_text))])
        else:
            self.source_map_fetches[row] = record
            self.source_map_fetch_model.setValueAt(str(status or "No response"), row, 1)
            self.source_map_fetch_model.setValueAt(str(len(response_text)), row, 2)
        if status == 200 and source is not None:
            self.support_sources[map_url] = source
            self._add_symbol_entries(entries, map_url)
        view_row = self.source_map_fetch_table.convertRowIndexToView(row)
        if view_row >= 0:
            self.source_map_fetch_table.setRowSelectionInterval(view_row, view_row)
            self._select_source_map_fetch()

    def _select_source_map_fetch(self):
        row = self.source_map_fetch_table.getSelectedRow()
        if row < 0:
            return
        row = self.source_map_fetch_table.convertRowIndexToModel(row)
        if row >= len(self.source_map_fetches):
            return
        record = self.source_map_fetches[row]
        self.source_map_request_area.setText(record.get("request", "") or
                                             "No HTTP request captured")
        self.source_map_response_area.setText(record.get("response", "") or
                                              "No HTTP response received")

    def _select_asset_row(self, table):
        row = table.getSelectedRow()
        if row >= 0:
            row = table.convertRowIndexToModel(row)
        if row < 0 or row >= len(self.asset_messages):
            return
        self._show_message(self.asset_messages[row])
        self.message_tabs.setSelectedIndex(1)

    def _show_message(self, message):
        request = message.getRequest()
        service = message.getHttpService()
        self.editor_http_service = service
        if service is None:
            info = self.helpers.analyzeRequest(request)
        else:
            info = self.helpers.analyzeRequest(service, request)
        self._set_request_message(request)
        self.input_area.setText(self.helpers.bytesToString(request[info.getBodyOffset():]))
        response = message.getResponse()
        self._set_response_message("No response saved" if response is None else response)

    def _select_source_row(self, table, evidence_column, url_column,
                           alternate_evidence_column=None):
        row = table.getSelectedRow()
        if row < 0:
            return
        row = table.convertRowIndexToModel(row)
        evidence = str(table.getValueAt(row, evidence_column) or "")
        alternate = ""
        if alternate_evidence_column is not None:
            alternate = str(table.getValueAt(row, alternate_evidence_column) or "")
        source_url = str(table.getValueAt(row, url_column))
        message = self._find_message_by_url(source_url)
        if message is not None:
            self._show_message(message)
            self.message_tabs.setSelectedIndex(1)
            found = self._highlight_message_text(
                self.response_editor, self.response_area, evidence)
            if not found and alternate:
                found = self._highlight_message_text(
                    self.response_editor, self.response_area, alternate)
        else:
            source = self.support_sources.get(source_url)
            if source is None:
                self._record("Navigate to evidence", "Source response is not available for %s" %
                             source_url)
                return
            self.editor_http_service = None
            self._set_request_message(
                "Source URL: %s\nNo captured HTTP request is available "
                "for this fetched support file." % source_url)
            self._set_response_message(source)
            self.message_tabs.setSelectedIndex(1)
            found = self._highlight_message_text(
                self.response_editor, self.response_area, evidence)
            if not found and alternate:
                found = self._highlight_message_text(
                    self.response_editor, self.response_area, alternate)
        if not found:
            self._record("Navigate to evidence", "Source loaded, but the selected text was not found")

    def _find_message_by_url(self, source_url):
        for message in self.history_messages + self.asset_messages:
            request = message.getRequest()
            if request is None:
                continue
            service = message.getHttpService()
            info = (self.helpers.analyzeRequest(request) if service is None else
                    self.helpers.analyzeRequest(service, request))
            if str(info.getUrl()) == source_url:
                return message
        return None

    @staticmethod
    def _highlight_text(area, value):
        if not value:
            return False
        text = area.getText()
        position = text.find(value)
        if position < 0:
            return False
        area.setCaretPosition(position)
        area.moveCaretPosition(position + len(value))
        area.requestFocusInWindow()
        return True

    @staticmethod
    def _highlight_message_text(editor, area, value):
        if not BurpExtender._highlight_text(area, value):
            return False
        search = getattr(editor, "setSearchExpression", None)
        if search is not None:
            try:
                search(value)
            except Exception:
                pass
        return True

    def _select_integrity_row(self):
        row = self.integrity_table.getSelectedRow()
        if row < 0:
            return
        row = self.integrity_table.convertRowIndexToModel(row)
        if row >= len(self.integrity_candidates) or self.integrity_request is None:
            return
        candidate = self.integrity_candidates[row]
        message = self._find_message_by_request(self.integrity_request)
        if message is not None:
            self._show_message(message)
        else:
            self.editor_http_service = self.loaded_service
            self._set_request_message(self.integrity_request)
            self._set_response_message("No response is available for this request")
        self.message_tabs.setSelectedIndex(1)
        field_name = candidate.get("name", "")
        value = candidate.get("value", "")
        if not self._highlight_message_text(self.request_editor, self.request_area, field_name):
            self._highlight_message_text(self.request_editor, self.request_area, value)

    def _find_message_by_request(self, request):
        request_text = self.helpers.bytesToString(request)
        for message in self.history_messages:
            candidate = message.getRequest()
            if (candidate is not None and
                    self.helpers.bytesToString(candidate) == request_text):
                return message
        return None

    def decode_selected_history(self):
        row = self.history_table.getSelectedRow()
        self._decode_history_row(row)

    def _select_history_row(self, table):
        self._decode_history_row(table.getSelectedRow())

    def _decode_history_row(self, row):
        if row >= 0:
            row = self.history_table.convertRowIndexToModel(row)
        if row < 0 or row >= len(self.history_messages):
            return
        message = self.history_messages[row]
        request = message.getRequest()
        service = message.getHttpService()
        if service is None:
            info = self.helpers.analyzeRequest(request)
        else:
            info = self.helpers.analyzeRequest(service, request)
        self.editor_http_service = service
        self.loaded_request = request
        self.loaded_service = service
        self._set_request_message(request)
        request_body = request[info.getBodyOffset():]
        self.input_area.setText(self.helpers.bytesToString(request_body))
        self.result_tabs.setSelectedIndex(2)
        self.parse_rpc()

        response = message.getResponse()
        if response is None:
            self._set_response_message("No response saved for this history entry")
            self.decoded_model.addRow(["Response", "missing", "", "", "No saved response"])
            self._record("Decode response", "No response saved for this history entry")
            return
        response_info = self.helpers.analyzeResponse(response)
        response_body = response[response_info.getBodyOffset():]
        response_text = self.helpers.bytesToString(response_body)
        self._set_response_message(response)
        response_type, response_payload = GwtResponse.decode(response_text)
        self.decoded_model.addRow(["HTTP status", "response", "", str(response_info.getStatusCode()),
                                   "Response status code"])
        self.decoded_model.addRow(["GWT envelope", response_type, "", response_type,
                                   "GWT-RPC response result"])
        self.decoded_model.addRow(["Response payload", "serialized", "", response_payload,
                                   "Decoded response body"])
        for path, value in GwtResponse.values(response_payload):
            self.decoded_model.addRow([path, "response value", "", str(value),
                                       "Decoded response field"])
        self.output_area.append(
            "Response HTTP %d\n%s\n%s\n" %
            (response_info.getStatusCode(),
             "\n".join(response_info.getHeaders()), response_text))
        self._record("Decode history", "%s (request and response)" % info.getUrl())

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        if hasattr(self, "history_model"):
            SwingUtilities.invokeLater(_UiUpdate(
                lambda: self._append_history_safely(message_info, "HTTP listener")))
        if message_is_request and self.auto_check.isSelected():
            self._observe_gwt_request(message_info)

    def processProxyMessage(self, message_is_request, message):
        """Capture traffic specifically processed by Burp Proxy."""
        if hasattr(self, "history_model"):
            message_info = message.getMessageInfo()
            SwingUtilities.invokeLater(_UiUpdate(
                lambda: self._append_history_safely(message_info, "Proxy listener")))

    def _append_history_safely(self, message, source):
        try:
            self._append_history_message(message)
        except Exception as error:
            self.callbacks.printError("%s entry error: %s" % (source, error))

    def _observe_gwt_request(self, message):
        try:
            request = message.getRequest()
            service = message.getHttpService()
            info = self.helpers.analyzeRequest(service, request)
            for header in info.getHeaders():
                if header.lower().startswith("content-type:") and "text/x-gwt-rpc" in header.lower():
                    self._record("Observed GWT request", str(info.getUrl()))
                    break
        except Exception as error:
            self.callbacks.printError("GWT request observation error: %s" % error)

    def parse_rpc(self):
        parsed = GwtRpc(self.input_area.getText()).parse()
        self.decoded_model.setRowCount(0)
        if parsed.error:
            self._record("Parse RPC", parsed.error)
            self.output_area.append("RPC decode failed: %s\n" % parsed.error)
            return
        self.decoded_model.addRow(["RPC version", "wire format", "0", self.input_area.getText().split("|")[0],
                                   "GWT-RPC protocol version"])
        self.decoded_model.addRow(["Host", "URL", "1", parsed.host, "RPC service host"])
        self.decoded_model.addRow(["Strong name", "hash", "2", parsed.strong_name,
                                   "GWT permutation identifier"])
        self.decoded_model.addRow(["Interface", "class", "3", parsed.interface_name,
                                   "RPC service interface"])
        self.decoded_model.addRow(["Method", "method", "4", parsed.method_name,
                                   "RPC method invoked"])
        for index, parameter in enumerate(parsed.parameters):
            self.decoded_model.addRow([
                "Parameter %d" % (index + 1), parameter["type"], parameter["index"],
                parameter["value"], "Serialized parameter value"])
        self.findings_model.addRow(["RPC method", parsed.interface_name + "." + parsed.method_name,
                                    "%d parameter(s), strong name %s" %
                                    (len(parsed.parameters), parsed.strong_name)])
        self.output_area.append(
            "RPC %s.%s\nHost: %s\nStrong name: %s\nParameters: %d\n" %
            (parsed.interface_name, parsed.method_name, parsed.host,
             parsed.strong_name, len(parsed.parameters)))
        for index, parameter in enumerate(parsed.parameters):
            self.output_area.append(
                "Parameter %d: type=%s, value-index=%s\n" %
                (index + 1, parameter["type"], parameter["index"]))

    def map_javascript(self):
        if SwingUtilities.isEventDispatchThread():
            Thread(_BackgroundTask(self._map_javascript)).start()
            return
        self._map_javascript()

    def _map_javascript(self):
        source = self.input_area.getText().strip()
        permutation = None
        if source.startswith("http://") or source.startswith("https://"):
            status, fetched, permutation = GwtMap.fetch_application(
                self.callbacks, self.helpers, source)
            if status != 200 or fetched is None:
                self._record("Map JavaScript", "HTTP %s" % status)
                return
            source = str(fetched)
            self.input_area.setText(source)
            self._record("Loaded permutation", str(permutation))
        services, methods, hashes = GwtMap.analyze(source)
        self.output_area.append("GWT map: %d service(s), %d method candidate(s), %d hash(es)\n" %
                                (len(services), len(methods), len(hashes)))
        if permutation is not None:
            self.output_area.append("Permutation and deferred fragments included\n")
        for service in services:
            self.findings_model.addRow(["Service", service["path"], service["strong_name"]])
            self.output_area.append("Service %s [%s]\n" %
                                    (service["path"], service["strong_name"]))
        for method in methods:
            self.findings_model.addRow(["Method", method, "JavaScript method candidate"])
            self.output_area.append("Method %s\n" % method)
        self._record("Map JavaScript", "%d service(s), %d method(s), %d hash(es)" %
                     (len(services), len(methods), len(hashes)))

    def fuzz_request(self):
        if SwingUtilities.isEventDispatchThread():
            if not self.active_check.isSelected():
                self._record("Fuzz", "Enable active replay / mutation before sending requests")
                return
            if self.loaded_request is None or self.loaded_service is None:
                self._record("Fuzz", "Load a full GWT request from the context menu first")
                return
            config = {
                "body": self.input_area.getText(),
                "strings": [line for line in self.strings_area.getText().splitlines() if line],
                "radius": int(self.range_spinner.getValue()),
                "maximum": int(self.max_requests_spinner.getValue()),
                "delay": int(self.delay_spinner.getValue()),
                "policy_types": self._policy_type_names(),
                "request": self.loaded_request,
                "service": self.loaded_service,
            }
            Thread(_BackgroundTask(lambda: self._fuzz_request(config))).start()
            return
        self._record("Fuzz", "Start fuzzing from the GWT RPC tab")

    def _policy_type_names(self):
        return [str(self.policy_model.getValueAt(row, 0))
                for row in range(self.policy_model.getRowCount())
                if str(self.policy_model.getValueAt(row, 0)).startswith("[") is False and
                str(self.policy_model.getValueAt(row, 0)) != "No fully qualified types detected"]

    def _make_fuzz_payloads(self):
        parsed = GwtRpc(self.input_area.getText()).parse()
        if parsed.error:
            return parsed, []
        strings = [line for line in self.strings_area.getText().splitlines() if line]
        maximum = int(self.max_requests_spinner.getValue())
        payloads = parsed.fuzz_payloads(strings, int(self.range_spinner.getValue()),
                        self._policy_type_names(), maximum + 1)
        return parsed, payloads

    def preview_fuzz_count(self):
        parsed, payloads = self._make_fuzz_payloads()
        if parsed.error:
            self.fuzz_count_label.setText("Fuzz requests: invalid RPC")
            self._record("Fuzz preview", parsed.error)
            return
        maximum = int(self.max_requests_spinner.getValue())
        planned = min(len(payloads), maximum)
        self.fuzz_count_label.setText("Fuzz requests: %d planned (hard cap %d)" %
                                       (planned, maximum))
        if len(payloads) > maximum:
            self._record("Fuzz preview", "At least %d generated; hard cap limits this run to %d" %
                         (len(payloads), maximum))
        else:
            self._record("Fuzz preview", "%d request(s)" % planned)

    def stop_fuzzing(self):
        if self.fuzz_running.get():
            self.stop_fuzz.set(True)
            self._record("Fuzz", "Stop requested; the current HTTP request will finish first")

    def _record_later(self, action, result):
        SwingUtilities.invokeLater(_UiUpdate(lambda: self._record(action, result)))

    def _request_info(self, request, service=None):
        if service is None:
            return self.helpers.analyzeRequest(request)
        return self.helpers.analyzeRequest(service, request)

    def _replace_request_body(self, request, payload, service=None):
        info = self._request_info(request, service)
        headers = [header for header in info.getHeaders()
                   if not header.lower().startswith("content-length:")]
        body = self.helpers.stringToBytes(payload)
        headers.append("Content-Length: %d" % len(body))
        return self.helpers.buildHttpMessage(headers, body)

    def _fuzz_request(self, config):
        if not self.fuzz_running.compareAndSet(False, True):
            self._record_later("Fuzz", "A fuzz run is already active")
            return
        self.stop_fuzz.set(False)
        SwingUtilities.invokeLater(_UiUpdate(lambda: self.stop_button.setEnabled(True)))
        try:
            parsed = GwtRpc(config["body"]).parse()
            if parsed.error:
                self._record_later("Fuzz", parsed.error)
                return
            maximum = config["maximum"]
            payloads = parsed.fuzz_payloads(config["strings"], config["radius"],
                                            config["policy_types"], maximum)
            delay = config["delay"]
            self._record_later("Fuzz", "Sending at most %d request(s), %d ms apart" %
                               (len(payloads), delay))
            sent = 0
            for label, payload in payloads:
                if self.stop_fuzz.get():
                    break
                rebuilt = self._replace_request_body(config["request"], payload,
                                                     config["service"])
                response = self.callbacks.makeHttpRequest(config["service"], rebuilt)
                raw_response = response.getResponse() if response is not None else None
                if raw_response is None:
                    result = "%s -> no response" % label
                else:
                    response_info = self.helpers.analyzeResponse(raw_response)
                    result = "%s -> HTTP %d (%d bytes)" % (
                        label, response_info.getStatusCode(), len(raw_response))
                self._record_later("Fuzz request", result)
                sent += 1
                if delay and sent < len(payloads) and not self.stop_fuzz.get():
                    remaining = delay
                    while remaining > 0 and not self.stop_fuzz.get():
                        interval = min(100, remaining)
                        Thread.sleep(interval)
                        remaining -= interval
            if self.stop_fuzz.get():
                self._record_later("Fuzz", "Stopped after %d request(s)" % sent)
            else:
                self._record_later("Fuzz", "Completed %d request(s)" % sent)
        except Exception as error:
            self._record_later("Fuzz", "Error: %s" % error)
        finally:
            self.fuzz_running.set(False)
            SwingUtilities.invokeLater(_UiUpdate(lambda: self.stop_button.setEnabled(False)))

    def _selected_history_message(self):
        row = self.history_table.getSelectedRow()
        if row < 0:
            return None
        row = self.history_table.convertRowIndexToModel(row)
        return self.history_messages[row] if 0 <= row < len(self.history_messages) else None

    @staticmethod
    def _is_auth_header(header_name):
        lowered = header_name.lower()
        return (lowered in ("authorization", "proxy-authorization", "cookie") or
                any(marker in lowered for marker in ("auth", "session", "token")))

    def set_alternate_session(self):
        message = self._selected_history_message()
        if message is None:
            self._record("Alternate session", "Select a captured request in History first")
            return
        info = self._request_info(message.getRequest(), message.getHttpService())
        headers = {}
        for header in info.getHeaders()[1:]:
            if ":" not in header:
                continue
            name, value = header.split(":", 1)
            if self._is_auth_header(name.strip()):
                headers[name.strip().lower()] = (name.strip(), value.strip())
        if not headers:
            self._record("Alternate session", "No authorization, session, or token headers found")
            return
        self.alternate_auth_headers = headers
        self.alternate_auth_source = str(info.getUrl())
        self._record("Alternate session", "Loaded %d auth header(s) from %s" %
                     (len(headers), self.alternate_auth_source))

    def compare_alternate_session(self):
        if not self.active_check.isSelected():
            self._record("Session comparison", "Enable active replay / mutation before sending requests")
            return
        if not self.alternate_auth_headers:
            self._record("Session comparison", "Set an alternate session from captured History first")
            return
        if self.loaded_request is None or self.loaded_service is None:
            self._record("Session comparison", "Select a captured baseline request first")
            return
        request = self.loaded_request
        service = self.loaded_service
        alternate = dict(self.alternate_auth_headers)
        source = self.alternate_auth_source
        Thread(_BackgroundTask(lambda: self._compare_alternate_request(
            request, service, alternate, source))).start()

    def _compare_alternate_request(self, request, service, alternate, source):
        info = self._request_info(request, service)
        headers = []
        replaced = set()
        for header in info.getHeaders():
            if ":" not in header:
                headers.append(header)
                continue
            name = header.split(":", 1)[0].strip().lower()
            if name in alternate:
                if name not in replaced:
                    headers.append("%s: %s" % alternate[name])
                    replaced.add(name)
            elif self._is_auth_header(name):
                continue
            else:
                headers.append(header)
        for name, value in alternate.values():
            if name.lower() not in replaced:
                headers.append("%s: %s" % (name, value))
        body = request[info.getBodyOffset():]
        changed_request = self.helpers.buildHttpMessage(headers, body)
        self._run_response_comparisons(
            "Session comparison (alternate from %s)" % source, service, request,
            [("alternate session", changed_request)])

    def _send_response_summary(self, service, request):
        response = self.callbacks.makeHttpRequest(service, request)
        raw = response.getResponse() if response is not None else None
        if raw is None:
            return {"status": "no response", "body": "", "envelope": "UNKNOWN", "values": {}}
        info = self.helpers.analyzeResponse(raw)
        body = self.helpers.bytesToString(raw[info.getBodyOffset():])
        envelope, payload = GwtResponse.decode(body)
        values = dict((path, str(value)) for path, value in GwtResponse.values(payload))
        return {"status": str(info.getStatusCode()), "body": body, "payload": payload,
            "envelope": envelope, "values": values}

    def _run_response_comparisons(self, title, service, baseline_request, variants):
        try:
            baseline = self._send_response_summary(service, baseline_request)
            baseline_line = "baseline HTTP %s, GWT %s, body %d bytes" % (
                baseline["status"], baseline["envelope"], len(baseline["body"]))
            self._record_later(title, baseline_line)
            for label, request in variants:
                result = self._send_response_summary(service, request)
                comparison = GwtResponse.compare(baseline, result)
                details = "%s: HTTP %s, GWT %s, body %d bytes, body changed=%s" % (
                    label, result["status"], result["envelope"], len(result["body"]),
                    "yes" if comparison["body_changed"] else "no")
                changed_paths = comparison["changed_paths"]
                if changed_paths:
                    details += "; changed response fields: " + ", ".join(changed_paths[:8])
                self._record_later(title, details)
        except Exception as error:
            self._record_later(title, "Error: %s" % error)

    @staticmethod
    def _looks_token_like(value):
        if len(value) < 24:
            return False
        has_letter = any(char.isalpha() for char in value)
        has_digit = any(char.isdigit() for char in value)
        return has_letter and has_digit and all(
            char.isalnum() or char in "-_=+/" for char in value)

    @staticmethod
    def _decode_urlencoded_pairs(source):
        pairs = []
        for item in (source or "").split("&"):
            if not item:
                continue
            name, separator, value = item.partition("=")
            try:
                name = URLDecoder.decode(name, "UTF-8")
                value = URLDecoder.decode(value if separator else "", "UTF-8")
            except Exception:
                value = value if separator else ""
            pairs.append([name, value])
        return pairs

    @staticmethod
    def _encode_urlencoded_pairs(pairs):
        return "&".join("%s=%s" % (URLEncoder.encode(name, "UTF-8"),
                                  URLEncoder.encode(value, "UTF-8"))
                        for name, value in pairs)

    def _scan_integrity_tokens(self, request, service=None):
        self.integrity_candidates = []
        self.integrity_model.setRowCount(0)
        self.integrity_request = request
        self.integrity_service = service
        info = self._request_info(request, service)

        def add(candidate, location, evidence):
            key = (candidate.get("kind"), candidate.get("name"), candidate.get("index"))
            if any((item.get("kind"), item.get("name"), item.get("index")) == key
                   for item in self.integrity_candidates):
                return
            self.integrity_candidates.append(candidate)
            shown = evidence if len(evidence) <= 14 else evidence[:5] + "..." + evidence[-5:]
            self.integrity_model.addRow([location, candidate.get("kind"), shown])

        token_name = __import__('re').compile(r"(?i)(csrf|xsrf|anti.?forgery|request.?verification)")
        query_pairs = self._decode_urlencoded_pairs(info.getUrl().getQuery())
        for index, (name, value) in enumerate(query_pairs):
            if token_name.search(name) or self._looks_token_like(value):
                add({"kind": "query", "name": name, "index": index, "value": value},
                    "Query: " + name, value)

        for header in info.getHeaders()[1:]:
            if ":" not in header:
                continue
            name, value = header.split(":", 1)
            name = name.strip()
            if token_name.search(name):
                add({"kind": "header", "name": name, "value": value.strip()},
                    "Header: " + name, value.strip())
            if name.lower() == "cookie":
                for cookie in value.split(";"):
                    if "=" not in cookie:
                        continue
                    cookie_name, cookie_value = cookie.strip().split("=", 1)
                    if token_name.search(cookie_name):
                        add({"kind": "cookie", "name": cookie_name,
                             "value": cookie_value}, "Cookie: " + cookie_name,
                            cookie_value)

        body = request[info.getBodyOffset():]
        is_form = any(header.lower().startswith("content-type:") and
                      "application/x-www-form-urlencoded" in header.lower()
                      for header in info.getHeaders())
        if is_form:
            for index, (name, value) in enumerate(
                    self._decode_urlencoded_pairs(self.helpers.bytesToString(body))):
                if token_name.search(name) or self._looks_token_like(value):
                    add({"kind": "form", "name": name, "index": index, "value": value},
                        "Form: " + name, value)

        parsed = GwtRpc(self.helpers.bytesToString(body)).parse()
        if not parsed.error:
            for number, parameter in enumerate(parsed.parameters):
                value_index = parameter.get("index")
                if value_index is None or value_index + 2 >= len(parsed.parts):
                    continue
                value = parsed.parts[value_index + 2]
                type_name = parameter.get("type", "")
                if (token_name.search(type_name) or self._looks_token_like(value)):
                    add({"kind": "rpc", "index": value_index, "value": value},
                        "RPC parameter %d (%s)" % (number + 1, type_name or "unknown"), value)
        return len(self.integrity_candidates)

    def find_integrity_tokens(self):
        if self.loaded_request is None:
            message = self._selected_history_message()
            if message is not None:
                self.loaded_request = message.getRequest()
                self.loaded_service = message.getHttpService()
        if self.loaded_request is None:
            self._record("Integrity scan", "Select a captured request in History first")
            return
        count = self._scan_integrity_tokens(self.loaded_request, self.loaded_service)
        self._record("Integrity scan", "%d candidate token field(s); heuristic only" % count)

    def probe_integrity_token(self):
        if not self.active_check.isSelected():
            self._record("Integrity probe", "Enable active replay / mutation before sending requests")
            return
        row = self.integrity_table.getSelectedRow()
        if row < 0 or self.loaded_request is None or self.loaded_service is None:
            self._record("Integrity probe", "Select a token candidate and captured RPC request first")
            return
        row = self.integrity_table.convertRowIndexToModel(row)
        if row >= len(self.integrity_candidates):
            return
        candidate = dict(self.integrity_candidates[row])
        request = self.loaded_request
        service = self.loaded_service
        Thread(_BackgroundTask(lambda: self._probe_integrity_candidate(
            request, service, candidate))).start()

    def _probe_integrity_candidate(self, request, service, candidate):
        info = self._request_info(request, service)
        body = request[info.getBodyOffset():]
        headers = list(info.getHeaders())
        variants = []
        kind = candidate["kind"]
        if kind == "header":
            name = candidate["name"]
            removed = [header for header in headers
                       if not header.lower().startswith(name.lower() + ":")]
            variants.append(("missing " + name,
                             self.helpers.buildHttpMessage(removed, body)))
            changed = [header for header in headers
                       if not header.lower().startswith(name.lower() + ":")]
            changed.append("%s: invalid-token" % name)
            variants.append(("changed " + name,
                             self.helpers.buildHttpMessage(changed, body)))
        elif kind == "cookie":
            cookie_header = next((header for header in headers
                                  if header.lower().startswith("cookie:")), None)
            if cookie_header is None:
                return
            cookie_name = candidate["name"]
            pairs = [item.strip() for item in cookie_header.split(":", 1)[1].split(";")
                     if "=" in item]
            missing_pairs = [item for item in pairs
                             if item.split("=", 1)[0].strip() != cookie_name]
            changed_pairs = [(cookie_name + "=invalid-token") if
                             item.split("=", 1)[0].strip() == cookie_name else item
                             for item in pairs]
            for label, selected in (("missing " + cookie_name, missing_pairs),
                                    ("changed " + cookie_name, changed_pairs)):
                replaced = False
                updated_headers = []
                for header in headers:
                    if header.lower().startswith("cookie:"):
                        updated_headers.append("Cookie: " + "; ".join(selected))
                        replaced = True
                    else:
                        updated_headers.append(header)
                if replaced:
                    variants.append((label, self.helpers.buildHttpMessage(updated_headers, body)))
        elif kind == "rpc":
            parsed = GwtRpc(self.helpers.bytesToString(body)).parse()
            index = candidate.get("index")
            if parsed.error or index is None or index + 2 >= len(parsed.parts):
                return
            for label, value in (("empty RPC token", ""), ("changed RPC token", "invalid-token")):
                parts = list(parsed.parts)
                parts[index + 2] = value
                changed_body = "|".join(parts)
                variants.append((label, self._replace_request_body(request, changed_body, service)))
        elif kind in ("query", "form"):
            source = (self.helpers.bytesToString(body) if kind == "form" else
                      info.getUrl().getQuery() or "")
            pairs = self._decode_urlencoded_pairs(source)
            index = candidate.get("index")
            if index is None or index >= len(pairs):
                return
            for label, value in (("empty " + kind + " token", ""),
                                 ("changed " + kind + " token", "invalid-token")):
                changed_pairs = [list(pair) for pair in pairs]
                changed_pairs[index][1] = value
                encoded = self._encode_urlencoded_pairs(changed_pairs)
                if kind == "form":
                    changed_request = self._replace_request_body(request, encoded, service)
                else:
                    changed_request = self._replace_query_string(request, service, encoded)
                variants.append((label, changed_request))
        if variants:
            self._run_response_comparisons("Integrity token probe", service, request, variants)

    def _replace_query_string(self, request, service, query):
        info = self._request_info(request, service)
        headers = list(info.getHeaders())
        request_parts = headers[0].split()
        if len(request_parts) < 3:
            return request
        path = info.getUrl().getPath() or "/"
        target = path + ("?" + query if query else "")
        headers[0] = "%s %s %s" % (request_parts[0], target, " ".join(request_parts[2:]))
        return self.helpers.buildHttpMessage(headers, request[info.getBodyOffset():])

    def clear_output(self):
        self.output_area.setText("")
