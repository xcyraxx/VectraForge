# -*- coding: utf-8 -*-
"""
BurpAI Extension for Burp Suite (Jython 2.7)
=============================================
Adds "Analyze with BurpAI" to the right-click context menu.
Sends the selected request to the local BurpAI server and
displays results in a dedicated Burp tab.

INSTALLATION:
  1. Extender > Options > Python Environment > set Jython JAR path
  2. Extender > Extensions > Add > Type: Python > select this file

REQUIREMENTS:
  - Jython 2.7+
  - BurpAI server running (python main.py --host 0.0.0.0 --port 8000)
"""

from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (
    JMenuItem, JPanel, JScrollPane, JTextArea,
    JLabel, JTabbedPane, SwingUtilities
)
from java.awt import BorderLayout, Font
from java.lang import Runnable
import java.net.URL as URL
import java.io.BufferedReader as BufferedReader
import java.io.InputStreamReader as InputStreamReader
import java.io.OutputStreamWriter as OutputStreamWriter
import json
import threading

# Change to Manjaro's IP if running server remotely
BURPAI_URL = "http://192.168.1.5:8000/analyze"


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpAI Vulnerability Analyzer")
        callbacks.registerContextMenuFactory(self)
        self._panel = self._build_ui()
        callbacks.addSuiteTab(self)
        self._log("BurpAI loaded. Server: " + BURPAI_URL)

    # --- ITab ----------------------------------------------------------------

    def getTabCaption(self):
        return "BurpAI"

    def getUiComponent(self):
        return self._panel

    # --- IContextMenuFactory -------------------------------------------------

    def createMenuItems(self, invocation):
        menu = []
        ctx = invocation.getInvocationContext()
        valid = [
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE,
        ]
        if ctx in valid:
            item = JMenuItem("Analyze with BurpAI")
            item.addActionListener(
                lambda e: threading.Thread(
                    target=self._analyze_request,
                    args=(invocation,)
                ).start()
            )
            menu.append(item)
        return menu

    # --- Analysis ------------------------------------------------------------

    def _analyze_request(self, invocation):
        try:
            messages = invocation.getSelectedMessages()
            if not messages:
                return

            msg = messages[0]
            request_bytes = msg.getRequest()
            request_info = self._helpers.analyzeRequest(msg)
            service = msg.getHttpService()

            raw_request = self._helpers.bytesToString(request_bytes)
            is_https = service.getProtocol().lower() == "https"
            target_host = service.getHost()

            self._log("Sending request to BurpAI: " + str(request_info.getUrl()))
            self._set_status("Analyzing... please wait")

            payload = json.dumps({
                "raw_request": raw_request,
                "target_host": target_host,
                "is_https": is_https,
            })

            result_json = self._post_to_server(payload)
            self._log("Raw response length: " + str(len(result_json)))
            self._log("First 200 chars: " + result_json[:200])

            # Strip BOM and whitespace that breaks Jython json.loads
            result_json = result_json.strip()
            if result_json.startswith("\xef\xbb\xbf"):
                result_json = result_json[3:]

            try:
                result = json.loads(result_json)
            except Exception as je:
                self._log("JSON parse error: " + str(je))
                # Show raw response in UI so we can debug
                SwingUtilities.invokeLater(
                    self._make_runnable(lambda: self._show_raw(result_json))
                )
                return

            SwingUtilities.invokeLater(
                self._make_runnable(lambda: self._display_result(result))
            )

        except Exception as e:
            self._log("Error: " + str(e))
            self._set_status("Error: " + str(e))

    def _post_to_server(self, payload):
        url = URL(BURPAI_URL)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setDoOutput(True)
        conn.setConnectTimeout(5000)
        conn.setReadTimeout(300000)

        writer = OutputStreamWriter(conn.getOutputStream())
        writer.write(payload)
        writer.flush()
        writer.close()

        code = conn.getResponseCode()
        stream = conn.getInputStream() if code == 200 else conn.getErrorStream()
        reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
        lines = []
        line = reader.readLine()
        while line is not None:
            lines.append(line)
            line = reader.readLine()
        reader.close()
        return "\n".join(lines)

    # --- UI ------------------------------------------------------------------

    def _build_ui(self):
        panel = JPanel(BorderLayout())

        self._status_label = JLabel("Ready -- right-click a request to analyze")
        self._status_label.setFont(Font("Monospaced", Font.PLAIN, 12))
        panel.add(self._status_label, BorderLayout.NORTH)

        self._tabs = JTabbedPane()

        self._summary_area  = self._make_text_area()
        self._vulns_area    = self._make_text_area()
        self._payloads_area = self._make_text_area()
        self._strategy_area = self._make_text_area()
        self._raw_area      = self._make_text_area()
        self._log_area      = self._make_text_area()

        self._tabs.addTab("Summary",  JScrollPane(self._summary_area))
        self._tabs.addTab("Vulns",    JScrollPane(self._vulns_area))
        self._tabs.addTab("Payloads", JScrollPane(self._payloads_area))
        self._tabs.addTab("Strategy", JScrollPane(self._strategy_area))
        self._tabs.addTab("Raw JSON", JScrollPane(self._raw_area))
        self._tabs.addTab("Log",      JScrollPane(self._log_area))

        panel.add(self._tabs, BorderLayout.CENTER)
        return panel

    def _make_text_area(self):
        area = JTextArea()
        area.setFont(Font("Monospaced", Font.PLAIN, 12))
        area.setEditable(False)
        area.setLineWrap(True)
        area.setWrapStyleWord(True)
        return area

    def _display_result(self, result):
        risk  = str(result.get("overall_risk_score", "?"))
        label = result.get("risk_label", "?").upper()
        url   = result.get("url", "?")
        vulns = result.get("vulnerabilities", [])
        strats = result.get("attack_strategies", [])
        obs   = result.get("interesting_observations", [])

        # Summary tab
        summary = []
        summary.append("=" * 60)
        summary.append("  BurpAI Analysis Report")
        summary.append("=" * 60)
        summary.append("URL:         " + url)
        summary.append("Method:      " + result.get("method", "?"))
        summary.append("Risk Score:  " + risk + "/10  [" + label + "]")
        summary.append("Vulns Found: " + str(len(vulns)))
        summary.append("Model:       " + result.get("model_used", "?"))
        summary.append("Time:        " + str(result.get("analysis_time_ms", "?")) + "ms")
        summary.append("")
        summary.append(result.get("surface_summary", ""))
        if obs:
            summary.append("")
            summary.append("INTERESTING OBSERVATIONS:")
            for o in obs:
                summary.append("  * " + o)
        self._summary_area.setText("\n".join(summary))

        # Vulns tab
        vlines = []
        for i, v in enumerate(vulns, 1):
            vlines.append("[" + str(i) + "] " + v.get("name", "?") + " -- " + v.get("severity", "?").upper())
            vlines.append("    Class:      " + v.get("vuln_class", "?"))
            vlines.append("    Confidence: " + v.get("confidence", "?"))
            vlines.append("    Params:     " + ", ".join(v.get("affected_params", [])))
            vlines.append("    CWE:        " + str(v.get("cwe_id", "?")))
            vlines.append("    OWASP:      " + str(v.get("owasp_category", "?")))
            vlines.append("    Description:")
            vlines.append("      " + v.get("description", ""))
            if v.get("evidence"):
                vlines.append("    Evidence: " + v["evidence"])
            if v.get("remediation"):
                vlines.append("    Fix: " + v["remediation"])
            vlines.append("")
        self._vulns_area.setText("\n".join(vlines))

        # Payloads tab
        plines = []
        for v in vulns:
            for p in v.get("payload_suggestions", []):
                plines.append("[" + v.get("name", "?") + "] param=" + p.get("parameter", "?"))
                plines.append("  Payload:   " + p.get("payload", "?"))
                plines.append("  Encoding:  " + str(p.get("encoding", "none")))
                plines.append("  Tests:     " + p.get("description", "?"))
                if p.get("expected_indicator"):
                    plines.append("  Indicator: " + p["expected_indicator"])
                plines.append("")
        self._payloads_area.setText("\n".join(plines))

        # Strategy tab
        slines = []
        sorted_strats = sorted(strats, key=lambda x: x.get("priority", 5))
        for s in sorted_strats:
            slines.append("[Priority " + str(s.get("priority", "?")) + "] " + s.get("title", "?"))
            slines.append("  Tools: " + ", ".join(s.get("tools", [])))
            slines.append("  Steps:")
            for step in s.get("steps", []):
                slines.append("    " + step)
            slines.append("")
        self._strategy_area.setText("\n".join(slines))

        # Raw JSON tab
        self._raw_area.setText(json.dumps(result, indent=2))

        self._set_status(
            "Done: " + str(len(vulns)) + " vulns | Risk: " + risk + "/10 [" + label + "]"
        )
        self._tabs.setSelectedIndex(0)

    def _show_raw(self, raw_text):
        """Display raw server response for debugging when JSON parse fails."""
        self._summary_area.setText("JSON PARSE FAILED\n\nRaw server response:\n\n" + raw_text)
        self._tabs.setSelectedIndex(0)
        self._set_status("Error: could not parse JSON response - check Summary tab")

    def _set_status(self, msg):
        SwingUtilities.invokeLater(
            self._make_runnable(lambda: self._status_label.setText(msg))
        )

    def _log(self, msg):
        self._callbacks.printOutput("[BurpAI] " + str(msg))
        try:
            current = self._log_area.getText()
            self._log_area.setText(current + "\n" + str(msg))
        except Exception:
            pass

    def _make_runnable(self, fn):
        class R(Runnable):
            def run(self_r):
                fn()
        return R()
