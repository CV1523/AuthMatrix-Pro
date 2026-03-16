# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab

from javax.swing import JTextField
from java.util import Arrays

from javax.swing import (
    JPanel, JTextArea, JScrollPane, JButton,
    JLabel, JComboBox, JFileChooser, JOptionPane, JCheckBox
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
from javax.swing.event import DocumentListener
from javax.swing import JTable
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.lang import Object

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
        self.unauth_status_codes = {}
        self.is_scanning = False
        self.esc_requests = {}
        self.esc_responses = {}
        self.esc_status_codes = {}
        self.esc_apis = set()

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
        
        right_top = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        # Search Field
        self.search_field = JTextField(15)
        from javax.swing.event import DocumentListener
        class SearchListener(DocumentListener):
            def __init__(self, extender): self.ext = extender
            def insertUpdate(self, e): self.ext.refresh_display(None)
            def removeUpdate(self, e): self.ext.refresh_display(None)
            def changedUpdate(self, e): self.ext.refresh_display(None)
        self.search_field.getDocument().addDocumentListener(SearchListener(self))

        right_top.add(JLabel("Search:"))
        right_top.add(self.search_field)
        right_top.add(JLabel("  |  "))

        self.refresh_button = JButton("Refresh Count", actionPerformed=self.refresh_display)
        self.clear_button = JButton("Clear APIs", actionPerformed=self.clear_apis)
        self.export_button = JButton("Export CSV", actionPerformed=self.export_csv)
        right_top.add(self.refresh_button)
        right_top.add(self.clear_button)
        right_top.add(self.export_button)

        right_top.add(JLabel(" |  Filter Method:"))
        self.method_filter_dropdown = JComboBox(["All"])
        self.method_filter_dropdown.addActionListener(self._on_filter_change)
        right_top.add(self.method_filter_dropdown)

        top_panel.add(left_top, BorderLayout.WEST)
        top_panel.add(right_top, BorderLayout.EAST)

        # ---------- Center (API TABLE & Viewers) ----------
        from javax.swing.table import DefaultTableModel
        from javax.swing import JTable
        from java.lang import Integer, String # Required for numerical sorting

        # FIX: Custom Table Model to force numerical sorting on Column 0
        class CustomTableModel(DefaultTableModel):
            def getColumnClass(self, columnIndex):
                if columnIndex == 0:
                    return Integer # Force S.NO to sort as a Number
                return String

        self.api_table_model = CustomTableModel(["S.NO", "Types", "API", "Unauthen-SC", "Unauthor-SC"], 0)
        self.api_table = JTable(self.api_table_model)
        self.api_table.setAutoCreateRowSorter(True)
        self.api_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        
        self.api_table.getColumnModel().getColumn(0).setPreferredWidth(40)
        self.api_table.getColumnModel().getColumn(1).setPreferredWidth(60)
        self.api_table.getColumnModel().getColumn(2).setPreferredWidth(350)
        self.api_table.getColumnModel().getColumn(3).setPreferredWidth(80)
        self.api_table.getColumnModel().getColumn(4).setPreferredWidth(80)
        
        def tableSelectionChanged(event):
            if not event.getValueIsAdjusting(): self.on_api_selected(None)
        self.api_table.getSelectionModel().addListSelectionListener(tableSelectionChanged)
        
        from java.lang import Object
        self.api_table.setDefaultRenderer(Object, ApiTableRenderer(self))

        api_scroll = JScrollPane(self.api_table)

        # ---- REQUEST TABS ----
        self.auth_request_viewer = self.callbacks.createMessageEditor(self, False)
        self.unauth_request_viewer = self.callbacks.createMessageEditor(self, False)
        self.esc_request_viewer = self.callbacks.createMessageEditor(self, False)

        self.request_tabs = JTabbedPane()
        self.request_tabs.addTab("Original Req", self.auth_request_viewer.getComponent())
        self.request_tabs.addTab("Unauth Req", self.unauth_request_viewer.getComponent())
        self.request_tabs.addTab("Escalation Req", self.esc_request_viewer.getComponent())

        # ---- RESPONSE TABS ----
        self.response_viewer = self.callbacks.createMessageEditor(self, False)
        self.esc_response_viewer = self.callbacks.createMessageEditor(self, False)

        self.response_tabs = JTabbedPane()
        self.response_tabs.addTab("Unauth Resp", self.response_viewer.getComponent())
        self.response_tabs.addTab("Escalation Resp", self.esc_response_viewer.getComponent())

        from javax.swing.event import ChangeListener
        class TabChangeListener(ChangeListener):
            def __init__(self, extender): self.extender = extender
            def stateChanged(self, event): self.extender.on_api_selected(None)
        
        self.request_tabs.addChangeListener(TabChangeListener(self))
        self.response_tabs.addChangeListener(TabChangeListener(self))

        request_panel = JPanel(BorderLayout())
        request_panel.add(self.request_tabs, BorderLayout.CENTER)

        response_panel = JPanel(BorderLayout())
        response_panel.add(self.response_tabs, BorderLayout.CENTER)

        right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, request_panel, response_panel)
        right_split.setResizeWeight(0.5)

        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, api_scroll, right_split)
        main_split.setResizeWeight(0.35)

        # ---------- Bottom bar (The Engine) ----------
        bottom_panel = JPanel(BorderLayout())
        auth_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self.auth_header_input = JTextField(12)
        self.include_unauth_cb = JCheckBox("Unauth Scan", True)
        self.esc_header_input = JTextField(20)

        self.verify_button = JButton("Start Access Control Scan", actionPerformed=self.verify_access_control)

        from java.awt import Dimension
        self.progress_bar = JProgressBar(0, 100)
        self.progress_bar.setStringPainted(True)
        self.progress_bar.setVisible(False)
        self.progress_bar.setPreferredSize(Dimension(120, 15))

        self.stop_button = JButton("Stop Scan", actionPerformed=self.request_stop)
        self.stop_button.setVisible(False)
        self.stop_button.setForeground(Color(200, 0, 0))

        auth_panel.add(JLabel("Auth Headers:"))
        auth_panel.add(self.auth_header_input)
        auth_panel.add(self.include_unauth_cb)
        auth_panel.add(JLabel("  |  Escalation Header:"))
        auth_panel.add(self.esc_header_input)
        auth_panel.add(self.verify_button)
        auth_panel.add(self.stop_button)
        auth_panel.add(self.progress_bar)

        credits_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        credits_label = JLabel("Built by HK@WhizzC  | GitHub")
        credits_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        credits_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        credits_label.addMouseListener(GitHubClickListener())
        credits_panel.add(credits_label)

        bottom_panel.add(auth_panel, BorderLayout.WEST)
        bottom_panel.add(credits_panel, BorderLayout.EAST)

        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(main_split, BorderLayout.CENTER)
        self.panel.add(bottom_panel, BorderLayout.SOUTH)

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
        view_row = self.api_table.getSelectedRow()
        if view_row == -1:
            # Clear all viewers if nothing is selected
            self.auth_request_viewer.setMessage(None, False)
            self.unauth_request_viewer.setMessage(None, False)
            self.esc_request_viewer.setMessage(None, False)
            self.response_viewer.setMessage(None, False)
            self.esc_response_viewer.setMessage(None, False)
            return

        # 1. Map View to Model for accurate data retrieval
        try:
            model_row = self.api_table.convertRowIndexToModel(view_row)
            method = self.api_table.getModel().getValueAt(model_row, 1)
            path = self.api_table.getModel().getValueAt(model_row, 2)
            selected_sig = "{} {}".format(method, path)
            
            data = self.api_requests.get(selected_sig)
        except:
            return

        if not data: return
        self.current_message = data

        # 2. Update REQUEST Viewers (3 Tabs)
        # Tab 0: Original | Tab 1: Unauth | Tab 2: Escalation
        req_tab = self.request_tabs.getSelectedIndex()
        
        if req_tab == 0:
            self.auth_request_viewer.setMessage(data["request"], True)
        elif req_tab == 1:
            u_req = self.unauth_requests.get(selected_sig)
            self.unauth_request_viewer.setMessage(u_req if u_req else b"", True)
        elif req_tab == 2:
            e_req = self.esc_requests.get(selected_sig)
            self.esc_request_viewer.setMessage(e_req if e_req else b"", True)

        # 3. Update RESPONSE Viewers (2 Tabs)
        # Tab 0: Unauth Response | Tab 1: Escalation Response
        res_tab = self.response_tabs.getSelectedIndex()
        
        if res_tab == 0:
            # Show Unauth Response captured during scan
            u_resp = self.unauth_responses.get(selected_sig)
            self.response_viewer.setMessage(u_resp if u_resp else b"", False)
        elif res_tab == 1:
            # Show Escalation Response captured during scan
            e_resp = self.esc_responses.get(selected_sig)
            self.esc_response_viewer.setMessage(e_resp if e_resp else b"", False)

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
        """Combines Method Filter and Search Keyword."""
        selected_method = self.method_filter_dropdown.getSelectedItem()
        search_query = self.search_field.getText().strip().lower()
        
        filtered = self.all_apis
        
        # Apply Method Filter
        if selected_method and selected_method != "All":
            prefix = selected_method + " "
            filtered = {api for api in filtered if api.startswith(prefix)}
            
        # Apply Search Keyword Filter
        if search_query:
            filtered = {api for api in filtered if search_query in api.lower()}
            
        return filtered
    
    # ---------------- Actions ---------------- #
    def refresh_display(self, event):
        self.api_table_model.setRowCount(0) # Clear table
        filtered_apis = sorted(self._get_filtered_apis())
        
        for i, api_sig in enumerate(filtered_apis):
            method, path = api_sig.split(" ", 1)
            # Retrieve status code if it exists from the unauth check
            u_code = self.unauth_status_codes.get(api_sig, "-")
            e_code = self.esc_status_codes.get(api_sig, "-")
            
            self.api_table_model.addRow([
                i + 1, 
                method, 
                path, 
                str(u_code), 
                str(e_code)
            ])
        
        self.count_label.setText("Total Unique APIs: {}".format(len(filtered_apis)))

    def clear_apis(self, event):
        # 1. Clear the underlying data dictionaries
        self.api_requests.clear()
        self.all_apis.clear()
        self.unauth_apis = set()
        self.unauth_requests.clear()
        self.unauth_responses.clear()
        self.unauth_status_codes.clear()
        
        # 2. Reset the Table Model (This replaces setListData)
        self.api_table_model.setRowCount(0)
        
        # 3. Clear the viewers
        self.auth_request_viewer.setMessage(None, False)
        self.unauth_request_viewer.setMessage(None, False)
        self.response_viewer.setMessage(None, False)
        
        # 4. Update the UI labels
        self.count_label.setText("Total Unique APIs: 0")
        self.callbacks.printOutput("[*] API list cleared.")

    def _on_options_change(self, event):
        self.exclude_options = (
            self.options_dropdown.getSelectedItem()
            == "Exclude OPTIONS"
        )
        self.refresh_display(None)

    def export_csv(self, event):
        row_count = self.api_table.getRowCount()
        
        if row_count == 0:
            from javax.swing import JOptionPane
            JOptionPane.showMessageDialog(self.panel, "No data visible to export.")
            return

        from javax.swing import JFileChooser
        from java.io import FileOutputStream, OutputStreamWriter
        import java.nio.charset.StandardCharsets as StandardCharsets
        
        chooser = JFileChooser()
        chooser.setDialogTitle("Save API List as CSV")

        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            if not file_path.lower().endswith(".csv"):
                file_path += ".csv"

            try:
                # Use FileOutputStream + OutputStreamWriter to force UTF-8 at the Java level
                fos = FileOutputStream(file_path)
                writer = OutputStreamWriter(fos, StandardCharsets.UTF_8)
                
                # Write Header
                writer.write(u"S.NO,Method,Path,Unauth Status,Escalation Status\n")
                
                for i in range(row_count):
                    sno = self.api_table.getValueAt(i, 0)
                    method = self.api_table.getValueAt(i, 1)
                    path = self.api_table.getValueAt(i, 2)
                    u_status = self.api_table.getValueAt(i, 3)
                    e_status = self.api_table.getValueAt(i, 4)
                                        
                    # Format the line as a Unicode string
                    line = u"{},{},{},{},{}\n".format(sno, method, unicode(path).replace(u",", u"%2C"), u_status, e_status)
                    writer.write(line)
                
                writer.close()
                self.callbacks.printOutput("[*] Successfully exported {} APIs (UTF-8) to {}".format(row_count, file_path))
                
            except Exception as e:
                self.callbacks.printError("[!] CSV Export failed: " + str(e))

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
        batch_size = 5
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
                    resp_info = self.helpers.analyzeResponse(response)
                    code = resp_info.getStatusCode()
                    self.unauth_status_codes[api] = code # Save the code here
                    if code < 400:
                        temp_unauth.add(api)

                current_count += 1
                val = current_count 
                SwingUtilities.invokeLater(PythonRunnable(lambda: self.progress_bar.setValue(val)))

                if current_count % batch_size == 0 or current_count == total_tasks:
                    self.unauth_apis = frozenset(temp_unauth)
                    
                    # CHANGE THIS LINE: from api_list to api_table
                    self.api_table.repaint() 
                    
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

    def _run_access_scan(self):
        import time
        from javax.swing import SwingUtilities
        
        # 1. Thread Safety Lock
        if hasattr(self, 'is_scanning') and self.is_scanning: return
        self.is_scanning = True
        self.stop_scan = False

        # Reset findings for the new scan
        self.unauth_apis = set()
        self.esc_apis = set()
        self.unauth_status_codes = {}
        self.esc_status_codes = {}
        
        scan_items = list(self.api_requests.items())
        total_tasks = len(scan_items)
        if total_tasks == 0:
            self.is_scanning = False
            return

        # --- UI LOCKDOWN: Disable buttons during scan ---
        def start_ui():
            self.verify_button.setEnabled(False)
            self.refresh_button.setEnabled(False) # Disable Refresh
            self.clear_button.setEnabled(False)   # Disable Clear
            self.export_button.setEnabled(False)  # Disable Export
            
            self.stop_button.setVisible(True)
            self.progress_bar.setMaximum(total_tasks)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
        SwingUtilities.invokeLater(PythonRunnable(start_ui))

        # Get inputs
        unauth_headers = [h.strip().lower() for h in self.auth_header_input.getText().split(",") if h.strip()]
        esc_header_full = self.esc_header_input.getText().strip()
        run_unauth = self.include_unauth_cb.isSelected()

        for current_count, (api, data) in enumerate(scan_items, 1):
            if self.stop_scan: break
            
            try:
                http_service = data["service"]
                orig_request = data["request"]
                req_info = self.helpers.analyzeRequest(http_service, orig_request)
                headers = list(req_info.getHeaders())
                body = orig_request[req_info.getBodyOffset():]

                # --- PHASE 1: UNAUTHENTICATED ---
                if run_unauth:
                    unauth_headers_list = [h for h in headers if h.split(":", 1)[0].lower() not in unauth_headers]
                    unauth_req = self.helpers.buildHttpMessage(unauth_headers_list, body)
                    self.unauth_requests[api] = unauth_req
                    
                    unauth_rr = self.callbacks.makeHttpRequest(http_service, unauth_req)
                    u_resp = unauth_rr.getResponse()
                    if u_resp:
                        self.unauth_responses[api] = u_resp
                        u_code = self.helpers.analyzeResponse(u_resp).getStatusCode()
                        self.unauth_status_codes[api] = u_code 
                        if u_code < 400:
                            self.unauth_apis.add(api)

                # --- PHASE 2: ESCALATION ---
                if ":" in esc_header_full:
                    target_header = esc_header_full.split(":", 1)[0].strip().lower()
                    esc_headers = []
                    replaced = False
                    
                    for h in headers:
                        if h.lower().startswith(target_header + ":"):
                            esc_headers.append(esc_header_full)
                            replaced = True
                        else:
                            esc_headers.append(h)
                    if not replaced: esc_headers.append(esc_header_full)

                    esc_req = self.helpers.buildHttpMessage(esc_headers, body)
                    self.esc_requests[api] = esc_req
                    
                    esc_rr = self.callbacks.makeHttpRequest(http_service, esc_req)
                    e_resp = esc_rr.getResponse()
                    if e_resp:
                        self.esc_responses[api] = e_resp
                        e_code = self.helpers.analyzeResponse(e_resp).getStatusCode()
                        self.esc_status_codes[api] = e_code 
                        if e_code == 200:
                            self.esc_apis.add(api)

                # Update Progress and live refresh
                SwingUtilities.invokeLater(PythonRunnable(lambda: self.progress_bar.setValue(current_count)))
                if current_count % 5 == 0 or current_count == total_tasks:
                    SwingUtilities.invokeLater(PythonRunnable(lambda: self.refresh_display(None)))

            except Exception as e:
                self.callbacks.printError("Scan Error: " + str(e))

        # --- UI UNLOCK: Restore button functionality ---
        def end_ui():
            self.progress_bar.setVisible(False)
            self.stop_button.setVisible(False)
            
            self.verify_button.setEnabled(True)
            self.refresh_button.setEnabled(True) # Re-enable Refresh
            self.clear_button.setEnabled(True)   # Re-enable Clear
            self.export_button.setEnabled(True)  # Re-enable Export
            
            self.is_scanning = False
            self.refresh_display(None)
        SwingUtilities.invokeLater(PythonRunnable(end_ui))

    def verify_access_control(self, event):
        """Triggered by the button click to start the multi-mode scan."""
        from java.lang import Thread
        # Start the scan in a background thread to keep the UI responsive
        t = Thread(PythonRunnable(self._run_access_scan))
        t.start()
    
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

class ApiTableRenderer(DefaultTableCellRenderer):
    def __init__(self, extender):
        self.extender = extender
        self.unauth_row = Color(140, 60, 60)   # Red
        self.selected_row = Color(75, 110, 175) # Blue
        self.even_row = Color(43, 43, 43)       # Dark Zebra
        self.odd_row = Color(52, 52, 52)        # Light Zebra

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        
        # 1. Map View index to Model index for sorting/filtering consistency
        try:
            model_row = table.convertRowIndexToModel(row)
            method = table.getModel().getValueAt(model_row, 1)
            path = table.getModel().getValueAt(model_row, 2)
            api_sig = "{} {}".format(method, path)
        except:
            api_sig = ""

        # 2. Handle Selection (Whole row highlight)
        if isSelected:
            c.setBackground(self.selected_row)
            c.setForeground(Color.WHITE)
            return c

        # 3. Apply Zebra Stripes as the base background
        c.setBackground(self.even_row if row % 2 == 0 else self.odd_row)
        c.setForeground(Color.WHITE)

        # 4. Apply Column-Specific Highlighting
        # Index 3: Unauth Status Column
        if column == 3 and api_sig in self.extender.unauth_apis:
            c.setBackground(Color(140, 60, 60))   # Dark Red
        
        # Index 4: Escalation Status Column
        elif column == 4 and api_sig in self.extender.esc_apis:
            c.setBackground(Color(200, 100, 0))  # Brighter Orange for contrast
            # c.setForeground(Color.BLACK) # Optional: Black text for orange
            
        self.setBorder(None)
        return c

class PythonRunnable(Runnable):
    def __init__(self, func): self.func = func
    def run(self): self.func()