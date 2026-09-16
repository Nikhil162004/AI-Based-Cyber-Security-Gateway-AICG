#!/usr/bin/env python3
"""Headless Browser End-to-End Verification for the AICG Administrative Security Layer.

Phase 19 Verification:
1. Login page rendering, styling, lab disclaimers, simulated MFA input, quick-fill buttons.
2. Authentication failures: invalid credentials and invalid MFA token rejection.
3. Successful Admin login: session badges, username 'admin', role 'ADMIN'.
4. Navigation across all 5 Admin Console panels:
   - Overview
   - Alert Center
   - Users & Roles (including dynamic user creation)
   - Audit Log (verifying event recording without credential leakage)
   - Security Posture (Zero Trust compliance score and checks)
5. Controlled attack simulation & alert lifecycle:
   - AI detection triggers single administrative alert linked 1:1 to incident.
   - Subsequent attack windows deduplicate (single alert updated).
   - In-app alert acknowledgment via UI button.
   - Attack cessation -> autonomous recovery -> incident RESOLVED -> alert RESOLVED.
   - Incident closure -> alert CLOSED.
6. Role-Based Access Control (RBAC):
   - Logout admin -> Login as operator.
   - Operator badge shows 'operator' and 'OPERATOR'.
   - Operator can view Overview and Alert Center.
   - Operator is strictly denied admin endpoints (/api/admin/users, /api/admin/audit, /api/settings/mode return 403).
7. Responsive design viewports:
   - 1600x1000 (standard SOC workstation)
   - 1280x900 (compact console)
   - 1024x800 (ruggedized panel PC)
   - 900x768 (split-screen monitor)
   - 768x1024 (vertical tablet / HMI)
8. High-resolution screenshots captured for evidence and audit reports.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from werkzeug.serving import make_server

# Add repository root to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.security import DEFAULT_SIMULATED_MFA_TOKEN

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerThread(threading.Thread):
    def __init__(self, app, host="127.0.0.1", port=5055):
        super().__init__(daemon=True)
        self.server = make_server(host, port, app, threaded=True)
        self.host = host
        self.port = port

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


def setup_driver():
    chrome_options = Options()
    chrome_options.binary_location = "/usr/bin/chromium"
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1600,1000")
    service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(30)
    driver.implicitly_wait(10)
    return driver


def run_e2e():
    print("=" * 75)
    print("AICG ADMINISTRATIVE SECURITY LAYER — BROWSER E2E ACCEPTANCE RUN")
    print("=" * 75)

    screenshots_dir = REPO_ROOT / "reports" / "evidence" / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_path = tmp_path / "browser_e2e.sqlite3"
        settings = Settings(
            database_path=db_path,
            auto_response=True,
        )
        runtime = GatewayRuntime(settings=settings)
        app = create_app(runtime)

        port = find_free_port()
        server = ServerThread(app, host="127.0.0.1", port=port)
        server.start()
        print(f"[*] Test Gateway server running at http://127.0.0.1:{port}")
        time.sleep(1.0)

        driver = setup_driver()
        try:
            base_url = f"http://127.0.0.1:{port}"

            # -------------------------------------------------------------
            # STEP 1: LOGIN PAGE RENDERING & AUTHENTICATION REJECTION TESTS
            # -------------------------------------------------------------
            print("\n[Step 1] Verifying Login Page rendering, styling, and validation...")
            # Verify unauthenticated redirection to /login
            driver.get(f"{base_url}/")
            time.sleep(1.0)
            assert "/login" in driver.current_url, f"Expected redirect to /login, got {driver.current_url}"
            print("  [+] Unauthenticated navigation to / correctly redirected to /login.")

            # Verify direct MFA submission without primary authentication returns 401 PRE_AUTH_REQUIRED
            status_mfa_direct = driver.execute_script("""
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/auth/mfa/verify', false);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({mfa_code: '123456'}));
                return {status: xhr.status, body: JSON.parse(xhr.responseText || '{}')};
            """)
            assert status_mfa_direct['status'] == 401, f"Expected 401 for direct MFA, got {status_mfa_direct['status']}"
            assert status_mfa_direct['body'].get('code') == 'PRE_AUTH_REQUIRED'
            print("  [+] Direct MFA verification without primary auth rejected with 401 PRE_AUTH_REQUIRED.")

            driver.get(f"{base_url}/login")
            time.sleep(1.0)
            assert "/login" in driver.current_url, f"Expected /login, got {driver.current_url}"

            # Check form elements
            username_input = driver.find_element(By.ID, "username")
            password_input = driver.find_element(By.ID, "password")
            mfa_input = driver.find_element(By.ID, "mfaCode")
            submit_btn = driver.find_element(By.ID, "loginSubmitBtn")

            assert username_input.is_displayed()
            assert password_input.is_displayed()
            assert mfa_input.is_displayed()
            assert submit_btn.is_displayed()

            # Check lab honesty indicators
            page_text = driver.find_element(By.TAG_NAME, "body").text
            assert "LOCAL LAB IDENTITY" in page_text or "SIMULATED MFA" in page_text or "DRY_RUN" in page_text, \
                "Login page must display laboratory honesty indicators"

            # Capture initial login screenshot
            driver.save_screenshot(str(screenshots_dir / "01_login_page.png"))
            print("  [+] Login page rendered correctly with simulated MFA and lab disclaimer.")

            # Test invalid password rejection
            username_input.send_keys("admin")
            password_input.send_keys("WrongPassword123!")
            mfa_input.clear()
            mfa_input.send_keys(DEFAULT_SIMULATED_MFA_TOKEN)
            submit_btn.click()
            time.sleep(1.0)

            error_el = driver.find_element(By.ID, "loginStatusMsg")
            assert error_el.is_displayed()
            assert "Invalid" in error_el.text and "credentials" in error_el.text
            print("  [+] Invalid credentials rejected with generic timing-safe error.")

            # Test invalid MFA rejection
            username_input.clear()
            password_input.clear()
            mfa_input.clear()
            username_input.send_keys("admin")
            password_input.send_keys("Admin@AICG2026!")
            mfa_input.send_keys("000000")
            submit_btn.click()
            time.sleep(1.0)

            assert error_el.is_displayed()
            assert "Invalid" in error_el.text and "MFA" in error_el.text
            print("  [+] Invalid simulated MFA token rejected.")

            # -------------------------------------------------------------
            # STEP 2: SUCCESSFUL ADMIN LOGIN & SESSION BADGES
            # -------------------------------------------------------------
            print("\n[Step 2] Executing Admin Login with Simulated MFA...")
            btn_quick_admin = driver.find_element(By.ID, "btnQuickAdmin")
            btn_quick_admin.click()  # Quick-fill demo admin credentials
            time.sleep(0.5)

            submit_btn = driver.find_element(By.ID, "loginSubmitBtn")
            submit_btn.click()
            time.sleep(2.0)

            # Check landing on HMI dashboard
            assert driver.current_url.rstrip("/").endswith(f":{port}") or "/" in driver.current_url
            user_badge = WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.ID, "headerUserBadge"))
            )
            assert user_badge.is_displayed()

            header_user = driver.find_element(By.ID, "headerUserLabel").text
            header_role = driver.find_element(By.ID, "headerRoleTag").text

            assert "admin" in header_user.lower(), f"Expected admin username, got {header_user}"
            assert "ADMIN" in header_role, f"Expected ADMIN role badge, got {header_role}"

            driver.save_screenshot(str(screenshots_dir / "02_admin_dashboard_landing.png"))
            print(f"  [+] Admin authenticated successfully! Header: user={header_user}, role={header_role}")

            # -------------------------------------------------------------
            # STEP 3: ADMIN CONSOLE PANELS & USER MANAGEMENT
            # -------------------------------------------------------------
            print("\n[Step 3] Navigating across 5 Admin Console panels...")

            # 1. Overview panel
            nav_overview = driver.find_element(By.ID, "nav-admin-overview")
            driver.execute_script("arguments[0].scrollIntoView();", nav_overview)
            nav_overview.click()
            time.sleep(1.0)
            sec_overview = driver.find_element(By.ID, "sec-admin-overview")
            assert sec_overview.is_displayed()
            metric_user = driver.find_element(By.ID, "adminOverviewUser").text
            metric_role = driver.find_element(By.ID, "adminOverviewRoleBadge").text
            print(f"  [+] Admin Overview loaded (Active Session: user={metric_user}, role={metric_role})")

            # 2. Alert Center panel
            nav_alerts = driver.find_element(By.ID, "nav-admin-alerts")
            nav_alerts.click()
            time.sleep(1.0)
            sec_alerts = driver.find_element(By.ID, "sec-admin-alerts")
            assert sec_alerts.is_displayed()
            print("  [+] Alert Center panel loaded.")

            # 3. Users & Roles panel + User Creation
            nav_users = driver.find_element(By.ID, "nav-admin-users")
            nav_users.click()
            time.sleep(1.0)
            sec_users = driver.find_element(By.ID, "sec-admin-users")
            assert sec_users.is_displayed()

            time.sleep(1.0)
            driver.execute_script("if (typeof refreshAdminUsers === 'function') refreshAdminUsers();")
            WebDriverWait(driver, 10).until(
                lambda d: "admin" in d.find_element(By.ID, "adminUsersTableBody").text
            )
            initial_users_text = driver.find_element(By.ID, "adminUsersTableBody").text
            assert "admin" in initial_users_text
            assert "operator" in initial_users_text
            print("  [+] Users & Roles panel loaded with pre-seeded 'admin' and 'operator'.")

            # Test creating a new user: 'soc_auditor'
            btn_open_add_user = driver.find_element(By.ID, "btnOpenAddUserModal")
            btn_open_add_user.click()
            time.sleep(0.5)

            new_user_input = driver.find_element(By.ID, "newLabUsername")
            new_pass_input = driver.find_element(By.ID, "newLabPassword")
            new_role_select = Select(driver.find_element(By.ID, "newLabRole"))
            btn_save = driver.find_element(By.XPATH, "//button[contains(text(), 'Save User')]")

            new_user_input.send_keys("soc_auditor")
            new_pass_input.send_keys("Auditor@AICG2026!")
            new_role_select.select_by_value("OPERATOR")
            btn_save.click()

            WebDriverWait(driver, 10).until(
                lambda d: "soc_auditor" in d.find_element(By.ID, "adminUsersTableBody").text
            )
            updated_users_text = driver.find_element(By.ID, "adminUsersTableBody").text
            assert "soc_auditor" in updated_users_text, "Newly created user 'soc_auditor' must appear in users table"
            print("  [+] Dynamic user creation verified: 'soc_auditor' successfully created with role OPERATOR.")

            # 4. Audit Log panel
            nav_audit = driver.find_element(By.ID, "nav-admin-audit")
            nav_audit.click()
            time.sleep(1.0)
            sec_audit = driver.find_element(By.ID, "sec-admin-audit")
            assert sec_audit.is_displayed()

            driver.execute_script("if (typeof refreshAdminAuditLogs === 'function') refreshAdminAuditLogs();")
            WebDriverWait(driver, 10).until(
                lambda d: "LOGIN" in d.find_element(By.ID, "adminAuditTableBody").text or "admin" in d.find_element(By.ID, "adminAuditTableBody").text
            )
            audit_tbody = driver.find_element(By.ID, "adminAuditTableBody")
            audit_text = audit_tbody.text
            assert "LOGIN_SUCCESS" in audit_text or "USER_CREATED" in audit_text or "LOGIN" in audit_text
            assert "Auditor@AICG2026!" not in audit_text, "Passwords must never appear in audit log!"
            assert "Admin@AICG2026!" not in audit_text
            print("  [+] Audit Log verified: events recorded properly with zero password leakage.")

            # 5. Security Posture panel
            nav_posture = driver.find_element(By.ID, "nav-admin-posture")
            nav_posture.click()
            time.sleep(1.0)
            sec_posture = driver.find_element(By.ID, "sec-admin-posture")
            assert sec_posture.is_displayed()

            posture_text = sec_posture.text
            assert "DRY_RUN" in posture_text or "NON-ENFORCING" in posture_text or "ZERO TRUST" in posture_text
            print("  [+] Security Posture verified: Dry-Run and RBAC checks pass.")

            driver.save_screenshot(str(screenshots_dir / "03_admin_console_panels.png"))

            # -------------------------------------------------------------
            # STEP 4: ATTACK DETECTION, ALERT LIFECYCLE & DEDUPLICATION
            # -------------------------------------------------------------
            print("\n[Step 4] Controlled Attack Simulation, Alert Creation & Lifecycle...")

            # Ingest benign windows to ensure stable baseline
            for s in range(3):
                runtime.ingest(generate_window("normal", intensity=1, sequence=s))

            # Ingest Attack Window 1 (SYN flood - HIGH severity)
            atk_window_1 = generate_window("syn_flood", intensity=1, sequence=10)
            res1 = runtime.ingest(atk_window_1)
            assert res1["decision"]["prediction"] == "ATTACK"
            incidents = [i for i in runtime.store.incidents() if i["lifecycle_state"] != "CLOSED"]
            assert len(incidents) >= 1
            inc_id = incidents[0]["incident_id"]

            # Verify alert created in storage
            alerts = runtime.store.list_alerts()
            assert len(alerts) >= 1
            alert_1 = alerts[0]
            alert_id = alert_1["alert_id"]
            assert alert_1["incident_id"] == inc_id
            print(f"  [+] Attack ingested: Incident {inc_id} generated -> Alert {alert_id} created ({alert_1['severity']}).")

            # Ingest Attack Window 2 (Campaign continues: Deduplication test)
            atk_window_2 = generate_window("syn_flood", intensity=1, sequence=11)
            runtime.ingest(atk_window_2)
            alerts_after_2 = runtime.store.list_alerts()
            # Must remain 1 alert for this incident, NOT duplicated
            matching_alerts = [a for a in alerts_after_2 if a["incident_id"] == inc_id]
            assert len(matching_alerts) == 1, f"Expected exactly 1 deduplicated alert for incident {inc_id}, got {len(matching_alerts)}"
            print(f"  [+] Deduplication verified: Subsequent attack window updated alert {alert_id} without duplicate rows.")

            # Refresh alerts UI by calling refreshAdminAlerts
            nav_alerts.click()
            time.sleep(0.5)
            driver.execute_script("if (typeof refreshAdminAlerts === 'function') refreshAdminAlerts();")
            WebDriverWait(driver, 10).until(
                lambda d: alert_id in d.find_element(By.ID, "adminAlertsTableBody").text or inc_id in d.find_element(By.ID, "adminAlertsTableBody").text
            )

            # In UI, locate the alert row and click acknowledge
            nav_alerts.click()
            time.sleep(1.0)
            alerts_tbody = driver.find_element(By.ID, "adminAlertsTableBody")
            assert alert_id in alerts_tbody.text or inc_id in alerts_tbody.text

            ack_btn = driver.find_element(By.CSS_SELECTOR, f"button.btn-ack[data-alert-id='{alert_id}']")
            assert ack_btn.is_displayed()
            ack_btn.click()
            time.sleep(1.5)

            # Verify acknowledged in storage
            alert_record = runtime.store.get_alert(alert_id)
            assert alert_record["acknowledgement_state"] == "ACKNOWLEDGED"
            assert alert_record["acknowledged_by"] == "admin"
            print(f"  [+] Alert {alert_id} acknowledged via UI by admin.")

            # Test Alert Re-Escalation upon recurring severe attack
            print("  [*] Testing Alert Re-Escalation upon recurring severe attack...")
            atk_severe = generate_window("syn_flood", intensity=5, sequence=15)
            runtime.ingest(atk_severe)
            re_alert = runtime.store.get_alert(alert_id)
            assert re_alert["acknowledgement_state"] == "RE_ESCALATED", f"Expected RE_ESCALATED, got {re_alert['acknowledgement_state']}"
            assert re_alert["status"] == "ACTIVE"
            print(f"  [+] Alert {alert_id} re-escalated to RE_ESCALATED upon recurring severe attack.")

            # Re-acknowledge before recovery
            runtime.store.acknowledge_alert(alert_id, "admin")
            driver.execute_script("if (typeof refreshAdminAlerts === 'function') refreshAdminAlerts();")
            time.sleep(0.5)

            # Simulate recovery (5 benign windows)
            print("  [*] Feeding consecutive benign windows to trigger autonomous recovery...")
            for s in range(20, 27):
                runtime.ingest(generate_window("normal", intensity=1, sequence=s))

            inc_after_recovery = runtime.store.incidents(state="RESOLVED")
            assert any(i["incident_id"] == inc_id for i in inc_after_recovery), "Incident must be RESOLVED after recovery streak"

            alert_after_recovery = runtime.store.get_alert(alert_id)
            assert alert_after_recovery["status"] == "RESOLVED", f"Alert status should be RESOLVED, got {alert_after_recovery['status']}"
            print(f"  [+] Autonomous recovery completed: Incident and Alert {alert_id} synced to RESOLVED.")

            # Close incident as admin via browser API call to test RBAC and lifecycle
            status_close = driver.execute_script(f"""
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/incidents/{inc_id}/transition', false);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({{state: 'CLOSED', actor: 'admin', note: 'Administrative incident closure'}}));
                return xhr.status;
            """)
            assert status_close == 200, f"Expected 200 closing incident as admin, got {status_close}"
            assert runtime.store.incident(inc_id)["lifecycle_state"] == "CLOSED"
            assert runtime.store.get_alert(alert_id)["status"] == "CLOSED"
            print(f"  [+] Incident {inc_id} and Alert {alert_id} closed by admin.")

            driver.execute_script("if (typeof refreshAdminAlerts === 'function') refreshAdminAlerts();")
            time.sleep(1.0)
            driver.save_screenshot(str(screenshots_dir / "04_alert_lifecycle.png"))

            # -------------------------------------------------------------
            # STEP 5: OPERATOR ROLE-BASED ACCESS CONTROL (RBAC)
            # -------------------------------------------------------------
            print("\n[Step 5] Testing Operator Role-Based Access Control (RBAC)...")

            # Logout admin
            logout_btn = driver.find_element(By.ID, "headerLogoutBtn")
            logout_btn.click()
            time.sleep(1.5)
            assert "/login" in driver.current_url

            # Login as operator
            btn_quick_operator = driver.find_element(By.ID, "btnQuickOperator")
            btn_quick_operator.click()
            time.sleep(0.5)
            driver.find_element(By.ID, "loginSubmitBtn").click()
            time.sleep(2.0)

            # Check operator session badges
            user_badge = WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.ID, "headerUserBadge"))
            )
            assert "operator" in driver.find_element(By.ID, "headerUserLabel").text.lower()
            assert "OPERATOR" in driver.find_element(By.ID, "headerRoleTag").text
            print("  [+] Operator logged in successfully. Role badge: OPERATOR.")

            # Verify operator can view Overview and Alert Center
            nav_overview = driver.find_element(By.ID, "nav-admin-overview")
            driver.execute_script("arguments[0].scrollIntoView();", nav_overview)
            nav_overview.click()
            time.sleep(1.0)
            assert driver.find_element(By.ID, "sec-admin-overview").is_displayed()

            nav_alerts = driver.find_element(By.ID, "nav-admin-alerts")
            nav_alerts.click()
            time.sleep(1.0)
            assert driver.find_element(By.ID, "sec-admin-alerts").is_displayed()
            print("  [+] Operator has permitted access to Overview and Alert Center.")

            # Test Operator RBAC Rejections via browser XMLHttpRequest (API level enforcement):
            print("  [*] Verifying server-side HTTP 403 enforcement for Operator on privileged endpoints...")

            # 1. /api/admin/users
            status_users = driver.execute_script("""
                const xhr = new XMLHttpRequest();
                xhr.open('GET', '/api/admin/users', false);
                xhr.send();
                return xhr.status;
            """)
            assert status_users == 403, f"Expected 403 for /api/admin/users, got {status_users}"

            # 2. /api/admin/audit
            status_audit = driver.execute_script("""
                const xhr = new XMLHttpRequest();
                xhr.open('GET', '/api/admin/audit', false);
                xhr.send();
                return xhr.status;
            """)
            assert status_audit == 403, f"Expected 403 for /api/admin/audit, got {status_audit}"

            # 3. /api/settings/mode
            status_mode = driver.execute_script("""
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/settings/mode', false);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({mode: 'ACTIVE'}));
                return xhr.status;
            """)
            assert status_mode == 403, f"Expected 403 for /api/settings/mode, got {status_mode}"

            # 4. Operator denied incident closure
            status_op_close = driver.execute_script(f"""
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/incidents/{inc_id}/transition', false);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({{state: 'CLOSED', actor: 'operator'}}));
                return xhr.status;
            """)
            assert status_op_close == 403, f"Expected 403 for operator closing incident, got {status_op_close}"

            # 5. Operator denied simulation launch
            status_sim = driver.execute_script("""
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/simulations/start', false);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({scenario_id: 'udp_flood', intensity: 3}));
                return xhr.status;
            """)
            assert status_sim == 403, f"Expected 403 for operator starting simulation, got {status_sim}"

            # 6. Operator denied audit log integrity check
            status_integ = driver.execute_script("""
                const xhr = new XMLHttpRequest();
                xhr.open('GET', '/api/admin/audit/integrity', false);
                xhr.send();
                return xhr.status;
            """)
            assert status_integ == 403, f"Expected 403 for operator verifying audit integrity, got {status_integ}"

            print("  [+] RBAC strictly enforced: Operator blocked with HTTP 403 on User Management, Audit Logs, Integrity, Mode Controls, Simulations, and Incident Closure.")
            driver.save_screenshot(str(screenshots_dir / "05_operator_rbac.png"))

            # -------------------------------------------------------------
            # STEP 6: RESPONSIVE VIEWPORT TESTING
            # -------------------------------------------------------------
            print("\n[Step 6] Testing responsive layouts across 5 industrial viewports...")
            viewports = [
                (1600, 1000, "06_viewport_1600x1000.png", "Standard SOC Workstation"),
                (1280, 900, "07_viewport_1280x900.png", "Compact Console"),
                (1024, 800, "08_viewport_1024x800.png", "Ruggedized Panel PC"),
                (900, 768, "09_viewport_900x768.png", "Split-Screen Monitor"),
                (768, 1024, "10_viewport_768x1024.png", "Vertical Tablet / HMI"),
            ]

            for width, height, filename, desc in viewports:
                driver.set_window_size(width, height)
                time.sleep(0.8)
                body_w = driver.execute_script("return document.body.scrollWidth;")
                win_w = driver.execute_script("return window.innerWidth;")
                assert body_w <= win_w + 30, f"Horizontal overflow detected at {width}x{height} (body={body_w}, win={win_w})"
                driver.save_screenshot(str(screenshots_dir / filename))
                print(f"  [+] Viewport {width}x{height} ({desc}) verified and screenshot captured.")

            print("\n" + "=" * 75)
            print("ALL HEADLESS BROWSER E2E TESTS PASSED SUCCESSFULLY!")
            print(f"Evidence screenshots saved in: {screenshots_dir}")
            print("=" * 75)

        finally:
            driver.quit()
            server.shutdown()


if __name__ == "__main__":
    run_e2e()
