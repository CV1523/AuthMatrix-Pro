# 🛡️ AuthMatrix Pro (formerly API Counter)
**Automated Broken Access Control (BAC) & IDOR Testing Suite for Burp Suite**

![Python](https://img.shields.io/badge/Language-Python%202.7-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Category](https://img.shields.io/badge/Category-Cybersecurity%20/%20Pentesting-red)

## 📖 Description
**AuthMatrix Pro** is a powerful Burp Suite extension designed for Hoodies to streamline the discovery and testing of API endpoints. It automates the tedious process of verifying **Unauthenticated Access** and **Privilege Escalation** (Vertical & Horizontal) vulnerabilities across large API surfaces.

## ✨ Key Features
* **Automatic API Discovery:** Passively maps unique API endpoints from Proxy and Repeater traffic.
* **Dual-Vector Scanning:**
    * **Unauth Scan:** Automatically strips session headers to find unprotected endpoints.
    * **Escalation Scan:** Replaces high-privilege headers with user-supplied low-privilege/victim tokens to test for BAC/IDOR.
* **Comparative Dashboard:** Side-by-side status code columns to instantly visualize security gaps.
* **Deep Inspection:** 5-Tab viewer system to compare Original, Unauthenticated, and Escalated requests/responses.
* **Smart Triage:** Numerical sorting, method filtering, and real-time keyword search.
* **Direct Export:** Export findings to UTF-8 encoded CSV for professional reporting.

## 🚀 Installation
1.  Ensure you have **Jython** configured in Burp Suite (Extender > Options > Python Environment).
2.  Download `Api_Counter.py` from this repository.
3.  In Burp, go to **Extensions** > **Installed** > **Add**.
4.  Select **Extension Type:** Python and choose `Api_Counter.py`.

## 🛠️ How to Use
### 1. Discovery
Simply browse the target application. The tool passively identifies unique `Method + Path` signatures and populates the table. Use the **Filter Method** or **Search** bar to narrow down targets.

### 2. Configuration
* **Auth Headers:** Enter headers to be removed during Unauth scans (e.g., `Cookie, Authorization`).
* **Escalation Header:** Enter the victim/low-privilege header you want to test (e.g., `Cookie: session=victim_token_here`).

### 3. Execution
Click **Start Access Control Scan**. The tool will perform the checks in the background.
* **Red Cells (Unauth):** Indicates the endpoint returned a success code (e.g., 200) without authentication.
* **Orange Cells (Escalation):** Indicates a potential Privilege Escalation/IDOR vulnerability.

### 4. Manual Verification
**Right-click** any row in the table to:
* Send Original Request to Repeater.
* Send Unauth Request to Repeater.
* Send Escalation Request to Repeater.

## 📄 License
This project is licensed under the MIT License.

## 👤 Credits
Built with ⚡ by [CV1523](https://github.com/CV1523) (HK@WhizzC)
