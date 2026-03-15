# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab

from javax.swing import JTextField
from java.util import Arrays

from javax.swing import (
    JPanel, JTextArea, JScrollPane, JButton,
    JLabel, JComboBox, JFileChooser
)
from java.awt import (
    BorderLayout, FlowLayout, Font,
    Cursor, Desktop
)
from java.awt.event import MouseAdapter
from java.net import URI
from java.io import FileWriter

from javax.swing import JList, JSplitPane, ListSelectionModel

from java.lang import Thread, Runnable
from javax.swing import DefaultListCellRenderer
from java.awt import Color
from burp import IMessageEditorController
from javax.swing import JTabbedPane
from javax.swing import DefaultComboBoxModel
import time
from javax.swing import SwingUtilities
from java.lang import Runnable
from javax.swing import JProgressBar

# -------- Mouse listener (Jython-safe) --------
class GitHubClickListener(MouseAdapter):
    def mouseClicked(self, event):
        try:
            Desktop.getDesktop().browse(
                URI("https://github.com/CV1523")
            )
        except:
            pass


class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.api_requests = {}
        self.unauth_apis = set()
        self.current_message = None
        self.unauth_requests = {}
        self.unauth_responses = {}
        self.is_scanning = False

        callbacks.setExtensionName("Unique API Counter")

        print("[+] Loading Unique API Counter extension...")

        # Store all APIs (method + path)
        self.all_apis = set()
        # self.api_list.setCellRenderer(ApiListRenderer(self))

        # Filter state
        self.exclude_options = False
        self.discovered_methods = set(["All"])


        self._build_ui()
        self._load_from_sitemapping()
        callbacks.registerHttpListener(self)

        self.refresh_display(None)

        # self._build_ui()
        callbacks.addSuiteTab(self)

    def _load_from_sitemapping(self):
        """Scans Burp's native Site Map to recover APIs stored in the project file."""
        # Passing None to getSiteMap returns the entire project site map
        site_map = self.callbacks.getSiteMap(None)
        
        self.callbacks.printOutput("[*] Syncing with native project logs...")
        
        for item in site_map:
            # Re-use the same logic as processHttpMessage
            request_info = self.helpers.analyzeRequest(item)
            url = request_info.getUrl()
            
            # Only sync items in scope to keep the tool clean
            if self.callbacks.isInScope(url):
                method = request_info.getMethod()
                path = url.getPath()
                
                # Filter out static noise (JS, CSS, etc.)
                ignore_ext = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg")
                if path.lower().endswith(ignore_ext):
                    continue

                api_signature = method + " " + path
                
                if api_signature not in self.all_apis:
                    self.all_apis.add(api_signature)
                    self.discovered_methods.add(method)
                    self.api_requests[api_signature] = {
                        "service": item.getHttpService(),
                        "request": item.getRequest(),
                        "response": item.getResponse(),
                        "method": method
                    }
        
        self._update_method_dropdown()

    # ---------------- UI ---------------- #
    def _build_ui(self):
        self.panel = JPanel(BorderLayout())

        # ---------- Top bar (Command Center) ----------
        top_panel = JPanel(BorderLayout())

        self.count_label = JLabel("Total Unique APIs: 0")
        self.count_label.setFont(Font("SansSerif", Font.BOLD, 13))

        left_top = JPanel(FlowLayout(FlowLayout.LEFT))
        left_top.add(self.count_label)

        # Container for Buttons + Filter
        right_top = JPanel(FlowLayout(FlowLayout.RIGHT))

        # 1. Initialize the buttons previously at the bottom
        self.refresh_button = JButton("Refresh Count", actionPerformed=self.refresh_display)
        self.clear_button = JButton("Clear APIs", actionPerformed=self.clear_apis)
        self.export_button = JButton("Export CSV", actionPerformed=self.export_csv)

        # 2. Add buttons to the top right
        right_top.add(self.refresh_button)
        right_top.add(self.clear_button)
        right_top.add(self.export_button)

        # 3. Add a separator and Method Filter
        right_top.add(JLabel(" |  Filter Method:"))
        self.method_filter_dropdown = JComboBox(["All"])
        self.method_filter_dropdown.addActionListener(self._on_filter_change)
        right_top.add(self.method_filter_dropdown)

        top_panel.add(left_top, BorderLayout.WEST)
        top_panel.add(right_top, BorderLayout.EAST)

        # ---------- Center (API List & Viewers) ----------
        self.api_list_model = []
        self.api_list = JList()
        self.api_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.api_list.addListSelectionListener(self.on_api_selected)
        self.api_list.setCellRenderer(ApiListRenderer(self))

        api_scroll = JScrollPane(self.api_list)

        self.auth_request_viewer = self.callbacks.createMessageEditor(self, False)
        self.unauth_request_viewer = self.callbacks.createMessageEditor(self, False)

        self.request_tabs = JTabbedPane()
        self.request_tabs.addTab("Request", self.auth_request_viewer.getComponent())
        self.request_tabs.addTab("Unauth Request", self.unauth_request_viewer.getComponent())

        from javax.swing.event import ChangeListener
        class TabChangeListener(ChangeListener):
            def __init__(self, extender): self.extender = extender
            def stateChanged(self, event): self.extender.on_api_selected(None)

        self.request_tabs.addChangeListener(TabChangeListener(self))

        self.response_viewer = self.callbacks.createMessageEditor(self, False)

        request_panel = JPanel(BorderLayout())
        request_panel.add(self.request_tabs, BorderLayout.CENTER)

        response_panel = JPanel(BorderLayout())
        response_panel.add(JLabel("Response"), BorderLayout.NORTH)
        response_panel.add(self.response_viewer.getComponent(), BorderLayout.CENTER)

        right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, request_panel, response_panel)
        right_split.setResizeWeight(0.5)

        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, api_scroll, right_split)
        main_split.setResizeWeight(0.3)

        # ---------- Bottom bar (Verification & Progress) ----------
        bottom_panel = JPanel(BorderLayout())

        # Left side: Auth configuration
        auth_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self.auth_header_input = JTextField(25)
        self.auth_header_input.setToolTipText("Headers to remove (comma separated)")

        self.verify_button = JButton("Verify Unauthenticated APIs", actionPerformed=self.verify_unauthenticated)

        # Progress bar setup
        from java.awt import Dimension
        self.progress_bar = JProgressBar(0, 100)
        self.progress_bar.setStringPainted(True)
        self.progress_bar.setVisible(False)
        self.progress_bar.setPreferredSize(Dimension(150, 10))

        auth_panel.add(JLabel("Auth Headers:"))
        auth_panel.add(self.auth_header_input)
        auth_panel.add(self.verify_button)
        auth_panel.add(self.progress_bar)

        # Right side: Credits
        credits_label = JLabel("Built by HK@WhizzC  | GitHub")
        credits_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        credits_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        credits_label.addMouseListener(GitHubClickListener())

        credits_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        credits_panel.add(credits_label)

        bottom_panel.add(auth_panel, BorderLayout.WEST)
        bottom_panel.add(credits_panel, BorderLayout.EAST)

        # ---------- Master Layout Assembly ----------
        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(main_split, BorderLayout.CENTER)
        self.panel.add(bottom_panel, BorderLayout.SOUTH)
        self.stop_button = JButton("Stop Scan", actionPerformed=self.request_stop)
        self.stop_button.setVisible(False)
        # self.stop_button.setForeground(Color.White)
        auth_panel.add(self.stop_button)

    # ---------------- HTTP Listener ---------------- #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        # 1. Quick Tool Filter
        tool_name = self.callbacks.getToolName(toolFlag)
        if tool_name not in ("Proxy", "Repeater"):
            return

        # 2. Extract info WITH service details to avoid the getUrl() error
        http_service = messageInfo.getHttpService() # Get service first
        request = messageInfo.getRequest()
        
        # Passing http_service here fixes the "UnsupportedOperationException"
        request_info = self.helpers.analyzeRequest(http_service, request)
        
        # 3. Get Method and URL Path
        method = request_info.getMethod()
        url = request_info.getUrl() # Now safe to call
        path = url.getPath()
        
        api_signature = method + " " + path
        self._detect_auth_headers(request_info.getHeaders())

        # 4. FAST EXIT: If we already have this API, stop immediately
        if api_signature in self.all_apis:
            return
        
        # 5. Scope-based filtering
        if not self.callbacks.isInScope(url):
            return

        # 6. OPTIONS filter
        ### if self.exclude_options and method == "OPTIONS":
            ### return
        
        # 7. Ignore static noise (performance boost)
        ignore_ext = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
            ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"
        )
        if path.lower().endswith(ignore_ext):
            return

        if method not in self.discovered_methods:
            self.discovered_methods.add(method)
            self._update_method_dropdown()

        # 8. Store the data
        self.all_apis.add(api_signature)
        self.api_requests[api_signature] = {
            "service": http_service,
            "request": request,
            "response": messageInfo.getResponse(),
            "method": method # Store method separately for easier filtering
        }

    def _detect_auth_headers(self, headers):
        """Identifies potential auth headers and suggests them in the UI."""
        # Common authentication/session header keywords
        auth_keywords = [
            "authorization", "bearer", "token", "jwt", "session", 
            "cookie", "api-key", "x-auth", "auth", "authorizationtoken"
        ]
        
        current_text = self.auth_header_input.getText().strip().lower()
        existing_filters = [h.strip() for h in current_text.split(",") if h.strip()]
        
        new_suggestions = []
        
        for header in headers:
            # Burp headers are "Header-Name: value" strings
            if ":" not in header: continue
            
            header_name = header.split(":", 1)[0].strip()
            header_name_lower = header_name.lower()
            
            # Check if header name contains any of our keywords
            if any(keyword in header_name_lower for keyword in auth_keywords):
                if header_name_lower not in existing_filters and header_name_lower not in new_suggestions:
                    new_suggestions.append(header_name)

        if new_suggestions:
            # Update the text field on the UI thread
            
            class UpdateText(Runnable):
                def __init__(self, field, suggestions, existing):
                    self.field = field
                    self.suggestions = suggestions
                    self.existing = existing
                def run(self):
                    combined = self.existing + self.suggestions
                    self.field.setText(", ".join(combined))
            
            SwingUtilities.invokeLater(UpdateText(self.auth_header_input, new_suggestions, existing_filters))

    def on_api_selected(self, event):
        if event.getValueIsAdjusting():
            return

        selected = self.api_list.getSelectedValue()
        if not selected:
            return

        data = self.api_requests.get(selected)
        if not data:
            return

        self.current_message = data

        self.auth_request_viewer.setMessage(
            data["request"], True
        )

        unauth_req = self.unauth_requests.get(selected)
        if unauth_req:
            self.unauth_request_viewer.setMessage(unauth_req, True)
        else:
            self.unauth_request_viewer.setMessage(None, False)

        if self.request_tabs.getSelectedIndex() == 1:
            unauth_resp = self.unauth_responses.get(selected)
            if unauth_resp:
                self.response_viewer.setMessage(unauth_resp, False)
            else:
                self.response_viewer.setMessage(None, False)
        else:
            # Show original authenticated response
            if data["response"]:
                self.response_viewer.setMessage(data["response"], False)
            else:
                self.response_viewer.setMessage(None, False)

    def _update_method_dropdown(self):
        """Refreshes the dropdown list without losing the current selection."""
        
        current_selection = self.method_filter_dropdown.getSelectedItem()
        
        # Sort methods but keep "All" at the top
        methods = sorted([m for m in self.discovered_methods if m != "All"])
        model = DefaultComboBoxModel(["All"] + methods)
        
        self.method_filter_dropdown.setModel(model)
        if current_selection in self.discovered_methods:
            self.method_filter_dropdown.setSelectedItem(current_selection)

    def _on_filter_change(self, event):
        self.refresh_display(None)

    # ---------------- Filtering ---------------- #
    def _get_filtered_apis(self):
        selected_method = self.method_filter_dropdown.getSelectedItem()
        if not selected_method or selected_method == "All":
            return self.all_apis
        
        # Filter set based on the prefix of the API signature (e.g., "GET ")
        prefix = selected_method + " "
        return {api for api in self.all_apis if api.startswith(prefix)}

    # ---------------- Actions ---------------- #
    def refresh_display(self, event):
        apis = sorted(self._get_filtered_apis())
        self.api_list_model = apis
        self.api_list.setListData(apis)
        self.count_label.setText(
            "Total Unique APIs: {}".format(len(apis))
        )

    def clear_apis(self, event):
        self.all_apis.clear()
        self.api_requests.clear()
        self.api_list.setListData([])
        self.count_label.setText("Total Unique APIs: 0")

    def _on_options_change(self, event):
        self.exclude_options = (
            self.options_dropdown.getSelectedItem()
            == "Exclude OPTIONS"
        )
        self.refresh_display(None)

    def export_csv(self, event):
        apis = sorted(self._get_filtered_apis())
        if not apis:
            return

        chooser = JFileChooser()
        chooser.setDialogTitle("Save API List as CSV")

        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(".csv"):
                path += ".csv"

            writer = FileWriter(path)
            writer.write("Method,Path\n")
            for api in apis:
                method, endpoint = api.split(" ", 1)
                writer.write("{},{}\n".format(method, endpoint))
            writer.close()

    def verify_unauthenticated(self, event):
        Thread(UnauthWorker(self)).start()

    def _run_unauth_checks(self):

        if hasattr(self, 'is_scanning') and self.is_scanning:
            return
        
        self.is_scanning = True
        self.stop_scan = False # Reset stop flag

        class PythonRunnable(Runnable):
            def __init__(self, func): self.func = func
            def run(self): self.func()

        raw_headers = self.auth_header_input.getText().strip()
        scan_items = list(self.api_requests.items())
        total_tasks = len(scan_items)
        
        if total_tasks == 0:
            self.is_scanning = False
            return

        # 1. LOCK ALL UI BUTTONS
        def lock_ui():
            self.verify_button.setEnabled(False)
            self.refresh_button.setEnabled(False)
            self.clear_button.setEnabled(False)
            self.export_button.setEnabled(False)
            self.stop_button.setVisible(True) # Show Stop button
            self.progress_bar.setMaximum(total_tasks)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
        SwingUtilities.invokeLater(PythonRunnable(lock_ui))

        if not raw_headers:
            self.callbacks.printOutput("[-] No auth headers provided")
            def abort():
                self.stop_button.setVisible(False)
                self.verify_button.setEnabled(True)
                self.refresh_button.setEnabled(True)
                self.clear_button.setEnabled(True)
                self.export_button.setEnabled(True)
                self.progress_bar.setVisible(False)
                self.is_scanning = False
            SwingUtilities.invokeLater(PythonRunnable(abort))
            return

        auth_headers = [h.strip().lower() for h in raw_headers.split(",")]
        temp_unauth = set()
        current_count = 0

        for api, data in scan_items:
            # 2. CHECK FOR STOP REQUEST
            if self.stop_scan:
                self.callbacks.printOutput("[!] Scan stopped by user.")
                break

            try:
                http_service = data["service"]
                request = data["request"]
                req_info = self.helpers.analyzeRequest(http_service, request)
                headers = list(req_info.getHeaders())
                body = request[req_info.getBodyOffset():]
                
                new_headers = [h for h in headers if h.split(":", 1)[0].lower() not in auth_headers]
                new_request = self.helpers.buildHttpMessage(new_headers, body)
                self.unauth_requests[api] = new_request

                rr = self.callbacks.makeHttpRequest(http_service, new_request)
                response = rr.getResponse()

                if response:
                    self.unauth_responses[api] = response
                    if self.helpers.analyzeResponse(response).getStatusCode() < 400:
                        temp_unauth.add(api)

                current_count += 1
                val = current_count 
                SwingUtilities.invokeLater(PythonRunnable(lambda: self.progress_bar.setValue(val)))

                if current_count % 5 == 0:
                    self.unauth_apis = frozenset(temp_unauth)
                    self.api_list.repaint()
                    time.sleep(0.01)

            except Exception as e:
                self.callbacks.printError("[ERROR] " + api + " -> " + str(e))

        # 3. UNLOCK ALL UI BUTTONS
        def final_ui():
            self.stop_button.setVisible(False)
            self.verify_button.setEnabled(True)
            self.refresh_button.setEnabled(True)
            self.clear_button.setEnabled(True)
            self.export_button.setEnabled(True)
            self.progress_bar.setVisible(False)
            self.is_scanning = False
            self.refresh_display(None)
            self.callbacks.printOutput("[*] Done.")

        SwingUtilities.invokeLater(PythonRunnable(final_ui))

    def request_stop(self, event):
        self.stop_scan = True
        self.callbacks.printOutput("[!] Stop request received. Finishing current task...")
    # ---------------- Tab ---------------- #
    def getTabCaption(self):
        return "API Counter"

    def getUiComponent(self):
        return self.panel

    def getHttpService(self):
        # if self.current_message:
        #     return self.current_message.getHttpService()
        # return None
        if self.current_message:
            return self.current_message["service"]
        return None

    def getRequest(self):
        # if self.current_message:
        #     return self.current_message.getRequest()
        # return None
        if self.current_message:
            return self.current_message["request"]
        return None

    def getResponse(self):
        # if self.current_message:
        #     return self.current_message.getResponse()
        # return None
        if self.current_message:
            return self.current_message["response"]
        return None

class UnauthWorker(Runnable):

    def __init__(self, extender):
        self.extender = extender

    def run(self):
        self.extender._run_unauth_checks()

class ApiListRenderer(DefaultListCellRenderer):
    def __init__(self, extender):
        self.extender = extender
        self.dark_row = Color(60, 63, 65)
        self.light_row = Color(69, 73, 74)
        self.unauth_row = Color(140, 60, 60)
        self.selected_row = Color(75, 110, 175)

    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        # Call super first for basic setup
        c = DefaultListCellRenderer.getListCellRendererComponent(
            self, list, value, index, isSelected, cellHasFocus
        )

        if isSelected:
            c.setBackground(self.selected_row)
        # Faster lookup: Ensure self.extender.unauth_apis is always a set or frozenset
        elif value in self.extender.unauth_apis:
            c.setBackground(self.unauth_row)
        else:
            c.setBackground(self.dark_row if index % 2 == 0 else self.light_row)

        c.setForeground(Color.WHITE)
        return c