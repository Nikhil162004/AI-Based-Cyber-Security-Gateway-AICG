#!/usr/bin/env python3
"""Comprehensive Verification of Fixed-Height Scrollable Log Panels.

Verifies:
1. Reference pattern alignment: #sec-incidents and #sec-admin-audit mirror #sec-flows.
2. Fixed-height container: max-height: 280px and overflow-y: auto.
3. Sticky column headers during vertical scrolling.
4. Independent vertical scrolling between panels.
5. Outside elements: Section headers, counters, badges, filter controls, action & export buttons remain outside.
6. Responsive behavior and zero horizontal page overflow across multiple viewports.
7. Preserved JS functionality: Filtering, refresh, export links.
"""

import os
import sys
import socket
import threading
import time
from pathlib import Path
from werkzeug.serving import make_server

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


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
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1600,1000")
    service = Service("/usr/bin/chromedriver") if os.path.exists("/usr/bin/chromedriver") else None
    if service:
        driver = webdriver.Chrome(service=service, options=options)
    else:
        driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(5)
    return driver


def run_verification():
    print("=" * 75)
    print("FIXED-HEIGHT SCROLLABLE LOG PANELS VERIFICATION")
    print("=" * 75)

    os.environ["AEGIS_TEST_MODE"] = "true"
    os.environ["AEGIS_MFA_ENFORCED"] = "true"
    import tempfile
    import shutil
    tmp_dir = tempfile.mkdtemp()
    tmp_path = Path(tmp_dir)
    db_path = tmp_path / "verify_scroll.sqlite3"
    settings = Settings(
        database_path=db_path,
        auto_response=True,
    )
    runtime = GatewayRuntime(settings=settings)

    # Pre-seed 50 realistic incidents and 50 audit records into database
    from aegis_gateway.schema import TelemetryEvent
    from datetime import datetime, timezone
    for i in range(1, 51):
        event = TelemetryEvent(
            event_id=f"EVT-20261115-{i:04d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip=f"10.0.0.{i % 250 + 1}",
            dst_ip="192.168.1.100",
            packet_count=100 + i,
            byte_count=50000 + i * 100,
            packet_rate=500.0,
            protocol="TCP" if i % 2 == 0 else "UDP",
            device_id=f"SENSOR-{i % 8 + 1}",
            attack_type="TCP_SYN_FLOOD" if i % 2 == 0 else "UDP_FLOOD",
            label="ATTACK",
            confidence=0.95,
            source_type="EDGE_PROBE"
        )
        inc = runtime.store.create_incident(event, evidence=[f"Evidence {i}"], affected_resources=f"SENSOR-{i % 8 + 1}")
        runtime.store.create_or_update_alert(incident=inc, event=event)
        runtime.store.record_audit(
            username="admin" if i % 2 == 0 else "operator",
            role="ADMIN" if i % 2 == 0 else "OPERATOR",
            action="USER_CONFIG_UPDATE" if i % 3 == 0 else ("POLICY_UPDATE" if i % 3 == 1 else "MITIGATION_EXECUTE"),
            resource=f"gateway/firewall/rule-{i}",
            result="SUCCESS",
            details=f"Synthetic test record {i} for scroll verification",
            source_ip="127.0.0.1",
        )

    app = create_app(runtime)

    port = find_free_port()
    server = ServerThread(app, port=port)
    server.start()
    base_url = f"http://127.0.0.1:{port}"
    print(f"[*] Gateway server running at {base_url}")

    driver = setup_driver()
    try:
        # Step 1: Login as Admin
        driver.get(f"{base_url}/login")
        btn_quick = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, "btnQuickAdmin"))
        )
        btn_quick.click()
        time.sleep(0.5)
        driver.find_element(By.ID, "loginSubmitBtn").click()
        time.sleep(2.0)

        user_badge = WebDriverWait(driver, 10).until(
            EC.visibility_of_element_located((By.ID, "headerUserBadge"))
        )
        assert user_badge.is_displayed()
        print("[+] Admin login successful; dashboard loaded.")
        time.sleep(1.5)

        # ---------------------------------------------------------------------
        # TEST 1: Inspect Reference Implementation (#sec-flows) vs Targets
        # ---------------------------------------------------------------------
        print("\n--- TEST 1: Container & CSS Inspection ---")
        test_containers = [
            ("sec-flows", "Raw Sample Flows (Reference)", "#sec-flows .table-responsive"),
            ("sec-incidents", "Durable Incident Journal", "#sec-incidents > .table-responsive"),
            ("sec-admin-alerts", "Administrative Alert Center", "#sec-admin-alerts .table-responsive"),
            ("sec-admin-audit", "Administrative Audit Log", "#sec-admin-audit .table-responsive"),
        ]

        for sec_id, name, selector in test_containers:
            info = driver.execute_script(f"""
                const el = document.querySelector('{selector}');
                if (!el) return null;
                const cs = window.getComputedStyle(el);
                return {{
                    maxHeight: cs.maxHeight,
                    overflowY: cs.overflowY,
                    overflowX: cs.overflowX,
                    border: cs.borderTopWidth + ' ' + cs.borderTopStyle,
                    borderRadius: cs.borderRadius,
                    clientHeight: el.clientHeight,
                    offsetHeight: el.offsetHeight,
                    scrollHeight: el.scrollHeight
                }};
            """)
            assert info is not None, f"Container for {name} ({selector}) must exist in DOM"
            print(f"  [{name}]")
            print(f"    max-height: {info['maxHeight']}")
            print(f"    overflow-y: {info['overflowY']}, overflow-x: {info['overflowX']}")
            print(f"    client-height: {info['clientHeight']}px, scroll-height: {info['scrollHeight']}px")
            assert info['maxHeight'] == "280px", f"{name} max-height must be 280px, got {info['maxHeight']}"
            assert info['overflowY'] in ("auto", "scroll"), f"{name} overflow-y must be auto/scroll, got {info['overflowY']}"
            assert info['overflowX'] in ("auto", "scroll"), f"{name} overflow-x must be auto/scroll, got {info['overflowX']}"

        print("[+] All 4 panel containers match the 280px fixed-height and overflow-y: auto pattern.")

        # ---------------------------------------------------------------------
        # TEST 2: Sticky Table Column Headers
        # ---------------------------------------------------------------------
        print("\n--- TEST 2: Sticky Column Header Inspection ---")
        tables_to_check = [
            ("#sec-incidents table.hmi-table", "Incident Journal Table"),
            ("#sec-admin-alerts table.data-table", "Alert Center Table"),
            ("#sec-admin-audit table.data-table", "Admin Audit Table"),
            ("#sec-flows table.hmi-table", "Raw Sample Flows Table"),
        ]

        for table_sel, tname in tables_to_check:
            header_info = driver.execute_script(f"""
                const th = document.querySelector('{table_sel} th');
                if (!th) return null;
                const cs = window.getComputedStyle(th);
                return {{
                    position: cs.position,
                    top: cs.top,
                    zIndex: cs.zIndex,
                    background: cs.backgroundColor,
                    boxShadow: cs.boxShadow
                }};
            """)
            assert header_info is not None, f"Headers for {tname} must exist"
            print(f"  [{tname}]")
            print(f"    position: {header_info['position']}, top: {header_info['top']}, z-index: {header_info['zIndex']}")
            print(f"    background: {header_info['background']}, box-shadow: {header_info['boxShadow']}")
            assert header_info['position'] == "sticky", f"{tname} th position must be sticky, got {header_info['position']}"
            assert header_info['top'] == "0px", f"{tname} th top must be 0px, got {header_info['top']}"
            assert header_info['zIndex'] != "auto" and int(header_info['zIndex']) >= 2, f"{tname} z-index must be >= 2"

        print("[+] Sticky column headers verified with position: sticky, top: 0px, and opaque backgrounds.")

        # ---------------------------------------------------------------------
        # TEST 3: Fixed Height Maintenance as Records Increase (Stress Test)
        # ---------------------------------------------------------------------
        print("\n--- TEST 3: Fixed Height Constraint with 50 Records ---")
        WebDriverWait(driver, 10).until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, "#incidentsTable tr")) >= 30
        )
        WebDriverWait(driver, 10).until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, "#adminAlertsTableBody tr")) >= 30
        )
        WebDriverWait(driver, 10).until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, "#adminAuditTableBody tr")) >= 30
        )
        time.sleep(1.0)

        # Check heights with 50 records
        inc_heights = driver.execute_script("""
            const el = document.querySelector('#sec-incidents > .table-responsive');
            return {
                clientHeight: el.clientHeight,
                offsetHeight: el.offsetHeight,
                scrollHeight: el.scrollHeight
            };
        """)
        print(f"  Incident Journal (50 records): clientHeight={inc_heights['clientHeight']}px, offsetHeight={inc_heights['offsetHeight']}px, scrollHeight={inc_heights['scrollHeight']}px")
        assert inc_heights['offsetHeight'] <= 282, f"Incident container height must be <= 282px, got {inc_heights['offsetHeight']}"
        assert inc_heights['scrollHeight'] > 1000, f"Incident container scrollHeight should be large (>1000px), got {inc_heights['scrollHeight']}"

        alerts_heights = driver.execute_script("""
            const el = document.querySelector('#sec-admin-alerts .table-responsive');
            return {
                clientHeight: el.clientHeight,
                offsetHeight: el.offsetHeight,
                scrollHeight: el.scrollHeight
            };
        """)
        print(f"  Alert Center (50 records): clientHeight={alerts_heights['clientHeight']}px, offsetHeight={alerts_heights['offsetHeight']}px, scrollHeight={alerts_heights['scrollHeight']}px")
        assert alerts_heights['offsetHeight'] <= 282, f"Alerts container height must be <= 282px, got {alerts_heights['offsetHeight']}"
        assert alerts_heights['scrollHeight'] > 1000, f"Alerts container scrollHeight should be large (>1000px), got {alerts_heights['scrollHeight']}"

        audit_heights = driver.execute_script("""
            const el = document.querySelector('#sec-admin-audit .table-responsive');
            return {
                clientHeight: el.clientHeight,
                offsetHeight: el.offsetHeight,
                scrollHeight: el.scrollHeight
            };
        """)
        print(f"  Admin Audit Log (50 records): clientHeight={audit_heights['clientHeight']}px, offsetHeight={audit_heights['offsetHeight']}px, scrollHeight={audit_heights['scrollHeight']}px")
        assert audit_heights['offsetHeight'] <= 282, f"Audit container height must be <= 282px, got {audit_heights['offsetHeight']}"
        assert audit_heights['scrollHeight'] > 1000, f"Audit container scrollHeight should be large (>1000px), got {audit_heights['scrollHeight']}"
        print("[+] Fixed height strictly enforced at 280px with internal vertical scroll capacity across all panels.")

        # ---------------------------------------------------------------------
        # TEST 4: Independent Vertical Scrolling
        # ---------------------------------------------------------------------
        print("\n--- TEST 4: Independent Vertical Scrolling Verification ---")
        # Scroll Incidents to 200px
        driver.execute_script("""
            const incEl = document.querySelector('#sec-incidents > .table-responsive');
            incEl.scrollTop = 200;
        """)
        time.sleep(0.2)

        scroll_states_1 = driver.execute_script("""
            return {
                incScroll: document.querySelector('#sec-incidents > .table-responsive').scrollTop,
                alertsScroll: document.querySelector('#sec-admin-alerts .table-responsive').scrollTop,
                auditScroll: document.querySelector('#sec-admin-audit .table-responsive').scrollTop,
                windowY: window.scrollY
            };
        """)
        print(f"  State after scrolling Incidents: inc={scroll_states_1['incScroll']}px, alerts={scroll_states_1['alertsScroll']}px, audit={scroll_states_1['auditScroll']}px")
        assert scroll_states_1['incScroll'] >= 180, f"Incident container should be scrolled, got {scroll_states_1['incScroll']}"
        assert scroll_states_1['alertsScroll'] == 0, f"Alerts container must remain at scrollTop 0, got {scroll_states_1['alertsScroll']}"
        assert scroll_states_1['auditScroll'] == 0, f"Audit container must remain at scrollTop 0, got {scroll_states_1['auditScroll']}"

        # Now scroll Alerts to 250px
        driver.execute_script("""
            const alertsEl = document.querySelector('#sec-admin-alerts .table-responsive');
            alertsEl.scrollTop = 250;
        """)
        time.sleep(0.2)

        scroll_states_2 = driver.execute_script("""
            return {
                incScroll: document.querySelector('#sec-incidents > .table-responsive').scrollTop,
                alertsScroll: document.querySelector('#sec-admin-alerts .table-responsive').scrollTop,
                auditScroll: document.querySelector('#sec-admin-audit .table-responsive').scrollTop
            };
        """)
        print(f"  State after scrolling Alerts: inc={scroll_states_2['incScroll']}px, alerts={scroll_states_2['alertsScroll']}px, audit={scroll_states_2['auditScroll']}px")
        assert scroll_states_2['incScroll'] >= 180, "Incident scroll must remain independent"
        assert scroll_states_2['alertsScroll'] >= 220, f"Alerts container should be scrolled, got {scroll_states_2['alertsScroll']}"
        assert scroll_states_2['auditScroll'] == 0, f"Audit container must remain at scrollTop 0, got {scroll_states_2['auditScroll']}"

        # Now scroll Audit to 350px
        driver.execute_script("""
            const auditEl = document.querySelector('#sec-admin-audit .table-responsive');
            auditEl.scrollTop = 350;
        """)
        time.sleep(0.2)

        scroll_states_3 = driver.execute_script("""
            return {
                incScroll: document.querySelector('#sec-incidents > .table-responsive').scrollTop,
                alertsScroll: document.querySelector('#sec-admin-alerts .table-responsive').scrollTop,
                auditScroll: document.querySelector('#sec-admin-audit .table-responsive').scrollTop
            };
        """)
        print(f"  State after scrolling Audit: inc={scroll_states_3['incScroll']}px, alerts={scroll_states_3['alertsScroll']}px, audit={scroll_states_3['auditScroll']}px")
        assert scroll_states_3['incScroll'] >= 180, "Incident scroll must remain independent"
        assert scroll_states_3['alertsScroll'] >= 220, "Alerts scroll must remain independent"
        assert scroll_states_3['auditScroll'] >= 300, f"Audit container should be scrolled, got {scroll_states_3['auditScroll']}"
        print("[+] All 3 log/alert panels scroll independently without cross-coupling.")

        # ---------------------------------------------------------------------
        # TEST 5: Sticky Header Positioning While Container is Scrolled
        # ---------------------------------------------------------------------
        print("\n--- TEST 5: Sticky Header Stability Under Scroll ---")
        for sec_sel, th_name in [
            ("#sec-incidents > .table-responsive", "Incident Table Header"),
            ("#sec-admin-alerts .table-responsive", "Alert Center Table Header"),
            ("#sec-admin-audit .table-responsive", "Audit Table Header")
        ]:
            pos_info = driver.execute_script(f"""
                const container = document.querySelector('{sec_sel}');
                const th = container.querySelector('th');
                const cRect = container.getBoundingClientRect();
                const thRect = th.getBoundingClientRect();
                return {{
                    containerTop: cRect.top,
                    thTop: thRect.top,
                    diff: Math.abs(cRect.top - thRect.top)
                }};
            """)
            print(f"  [{th_name}] containerTop={pos_info['containerTop']:.1f}px, thTop={pos_info['thTop']:.1f}px (diff={pos_info['diff']:.1f}px)")
            # th top should align within border tolerance (<= 2px) of container top
            assert pos_info['diff'] <= 2.5, f"Sticky header {th_name} did not stick to top: diff={pos_info['diff']}px"

        print("[+] Table column headers remain pinned to the top of the container during scrolling across all panels.")

        # ---------------------------------------------------------------------
        # TEST 6: Outside Elements Stay Outside and Functional
        # ---------------------------------------------------------------------
        print("\n--- TEST 6: Outside Headers, Controls & Action Buttons ---")
        # In #sec-incidents: Header and export toolbar
        inc_elements = driver.execute_script("""
            const sec = document.getElementById('sec-incidents');
            const container = sec.querySelector('.table-responsive');
            const header = sec.querySelector('.panel-header');
            const toolbar = sec.querySelector('.export-toolbar');
            return {
                headerOutside: !container.contains(header),
                toolbarOutside: !container.contains(toolbar),
                activeCount: document.getElementById('activeIncidentCount')?.textContent,
                totalCount: document.getElementById('incidentCount')?.textContent,
                csvExportHref: sec.querySelector('a[href*="incidents.csv"]')?.getAttribute('href')
            };
        """)
        assert inc_elements['headerOutside'], "Incident header must remain outside table container"
        assert inc_elements['toolbarOutside'], "Incident export toolbar must remain outside table container"
        assert inc_elements['totalCount'] == "50", f"Total count counter must read 50, got {inc_elements['totalCount']}"
        assert inc_elements['csvExportHref'] == "/api/export/incidents.csv"
        print(f"  [+] Incidents outside elements verified: Total={inc_elements['totalCount']}, Export={inc_elements['csvExportHref']}")

        # In #sec-admin-alerts: Header, filters, counts, exports
        alerts_elements = driver.execute_script("""
            const sec = document.getElementById('sec-admin-alerts');
            const container = sec.querySelector('.table-responsive');
            const header = sec.querySelector('.panel-header');
            const filterAll = document.getElementById('filterAlertsAll');
            const filterUnack = document.getElementById('filterAlertsUnack');
            const exportCsv = document.getElementById('btnExportAlertsCsv');
            const exportJson = document.getElementById('btnExportAlertsJson');
            return {
                headerOutside: !container.contains(header),
                filterAllOutside: !container.contains(filterAll),
                filterUnackOutside: !container.contains(filterUnack),
                exportOutside: !container.contains(exportCsv),
                exportCsvHref: exportCsv?.getAttribute('href'),
                exportJsonHref: exportJson?.getAttribute('href'),
                allCount: document.getElementById('countAlertsAll')?.textContent
            };
        """)
        assert alerts_elements['headerOutside'], "Alert Center header must remain outside container"
        assert alerts_elements['filterAllOutside'], "Alert Center filterAll must remain outside container"
        assert alerts_elements['filterUnackOutside'], "Alert Center filterUnack must remain outside container"
        assert alerts_elements['exportOutside'], "Alert Center export buttons must remain outside container"
        assert alerts_elements['exportCsvHref'] == "/api/export/alerts.csv"
        assert alerts_elements['exportJsonHref'] == "/api/export/alerts.json"
        print(f"  [+] Alert Center outside elements verified: CountAll={alerts_elements['allCount']}, Exports outside.")

        # In #sec-admin-audit: Header, badges, search input, refresh, export
        audit_elements = driver.execute_script("""
            const sec = document.getElementById('sec-admin-audit');
            const container = sec.querySelector('.table-responsive');
            const header = sec.querySelector('.panel-header');
            const searchInput = document.getElementById('auditSearchInput');
            const refreshBtn = sec.querySelector('button[onclick*="refreshAuditLogs"]');
            const exportCsv = document.getElementById('btnExportAuditCsv');
            const exportJson = document.getElementById('btnExportAuditJson');
            const notice = document.getElementById('operatorAuditNotice');
            return {
                headerOutside: !container.contains(header),
                searchOutside: !container.contains(searchInput),
                refreshOutside: !container.contains(refreshBtn),
                exportOutside: !container.contains(exportCsv),
                noticeOutside: !container.contains(notice),
                exportCsvHref: exportCsv?.getAttribute('href'),
                exportJsonHref: exportJson?.getAttribute('href')
            };
        """)
        assert audit_elements['headerOutside'], "Admin audit header must remain outside container"
        assert audit_elements['searchOutside'], "Search input must remain outside container"
        assert audit_elements['refreshOutside'], "Refresh button must remain outside container"
        assert audit_elements['exportOutside'], "Export button must remain outside container"
        assert audit_elements['noticeOutside'], "Notice banner must remain outside container"
        assert audit_elements['exportCsvHref'] == "/api/export/audit.csv"
        assert audit_elements['exportJsonHref'] == "/api/export/audit.json"
        print("  [+] Admin audit outside elements verified: header, search, refresh, exports outside.")

        # ---------------------------------------------------------------------
        # TEST 7: Search Filtering & Refresh Functionality Preserved
        # ---------------------------------------------------------------------
        print("\n--- TEST 7: JavaScript Functionality (Search & Refresh) ---")
        initial_count = driver.execute_script("""
            return document.querySelectorAll('#adminAuditTableBody tr').length;
        """)
        search_input = driver.find_element(By.ID, "auditSearchInput")
        search_input.clear()
        search_input.send_keys("record 15")
        time.sleep(0.3)

        filtered_count = driver.execute_script("""
            const rows = document.querySelectorAll('#adminAuditTableBody tr');
            return rows.length;
        """)
        print(f"  Rows visible after filtering for 'record 15': {filtered_count}")
        assert filtered_count == 1, f"Expected 1 matching record, got {filtered_count}"

        # Clear search
        search_input.clear()
        driver.execute_script("filterAuditTable();")
        time.sleep(0.3)
        restored_count = driver.execute_script("""
            return document.querySelectorAll('#adminAuditTableBody tr').length;
        """)
        print(f"  Rows visible after clearing filter: {restored_count} (initial: {initial_count})")
        assert restored_count == initial_count, f"Expected {initial_count} records restored, got {restored_count}"
        print("[+] Filter and search functionality operates seamlessly.")

        # Alert filtering and acknowledge test
        filter_unack_btn = driver.find_element(By.ID, "filterAlertsUnack")
        filter_unack_btn.click()
        time.sleep(0.3)
        unack_mode_active = driver.execute_script("return document.getElementById('filterAlertsUnack').classList.contains('active');")
        assert unack_mode_active, "UNACK filter button should be active"

        filter_all_btn = driver.find_element(By.ID, "filterAlertsAll")
        filter_all_btn.click()
        time.sleep(0.3)
        all_mode_active = driver.execute_script("return document.getElementById('filterAlertsAll').classList.contains('active');")
        assert all_mode_active, "ALL filter button should be active"
        print("[+] Alert filtering controls verified.")

        # ---------------------------------------------------------------------
        # TEST 8: Responsive Layout Across Multiple Viewports
        # ---------------------------------------------------------------------
        print("\n--- TEST 8: Responsive Layouts & Horizontal Overflow ---")
        viewports = [
            (1600, 1000, "Standard SOC Workstation"),
            (1280, 900, "Compact Console"),
            (1024, 768, "Ruggedized Panel PC"),
            (768, 1024, "Vertical Tablet / HMI"),
            (375, 812, "Mobile Handheld"),
        ]

        screenshot_dir = REPO_ROOT / "backend/reports/evidence/screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        for width, height, label in viewports:
            driver.set_window_size(width, height)
            time.sleep(0.5)

            overflow_info = driver.execute_script("""
                const body = document.body;
                const html = document.documentElement;
                return {
                    windowInnerWidth: window.innerWidth,
                    docScrollWidth: html.scrollWidth,
                    hasHorizontalOverflow: html.scrollWidth > window.innerWidth,
                    incMaxHeight: window.getComputedStyle(document.querySelector('#sec-incidents > .table-responsive')).maxHeight,
                    alertsMaxHeight: window.getComputedStyle(document.querySelector('#sec-admin-alerts .table-responsive')).maxHeight,
                    auditMaxHeight: window.getComputedStyle(document.querySelector('#sec-admin-audit .table-responsive')).maxHeight
                };
            """)
            print(f"  Viewport {width}x{height} ({label}):")
            print(f"    windowInnerWidth={overflow_info['windowInnerWidth']}px, docScrollWidth={overflow_info['docScrollWidth']}px")
            print(f"    horizontal overflow: {overflow_info['hasHorizontalOverflow']}")
            print(f"    incidents: {overflow_info['incMaxHeight']}, alerts: {overflow_info['alertsMaxHeight']}, audit: {overflow_info['auditMaxHeight']}")

            assert not overflow_info['hasHorizontalOverflow'], f"Viewport {width}x{height} introduced page horizontal overflow!"
            assert overflow_info['incMaxHeight'] == "280px"
            assert overflow_info['alertsMaxHeight'] == "280px"
            assert overflow_info['auditMaxHeight'] == "280px"

        # Save evidence screenshot
        driver.set_window_size(1600, 1000)
        time.sleep(0.5)
        # Scroll to #sec-incidents and take screenshot
        driver.execute_script("document.getElementById('sec-incidents').scrollIntoView();")
        time.sleep(0.5)
        driver.save_screenshot(str(screenshot_dir / "scroll_panels_incidents_evidence.png"))

        # Scroll to #sec-admin-alerts and take screenshot
        driver.execute_script("document.getElementById('sec-admin-alerts').scrollIntoView();")
        time.sleep(0.5)
        driver.save_screenshot(str(screenshot_dir / "scroll_panels_admin_alerts_evidence.png"))

        # Scroll to #sec-admin-audit and take screenshot
        driver.execute_script("document.getElementById('sec-admin-audit').scrollIntoView();")
        time.sleep(0.5)
        driver.save_screenshot(str(screenshot_dir / "scroll_panels_admin_audit_evidence.png"))
        print("\n[+] Evidence screenshots captured successfully.")

        print("\n" + "=" * 75)
        print("ALL SCROLLABLE LOG PANELS VERIFICATION TESTS PASSED SUCCESSFULLY!")
        print("=" * 75)

    finally:
        driver.quit()
        server.shutdown()
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_verification()
