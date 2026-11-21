#!/usr/bin/env python3
"""Verification and screenshot capture script for the Protocol Mix Visual Redesign."""

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
from selenium.webdriver.common.action_chains import ActionChains
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
    chrome_options = Options()
    chrome_options.binary_location = "/usr/bin/chromium"
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1600,1050")
    service = Service("/usr/bin/chromedriver")
    return webdriver.Chrome(service=service, options=chrome_options)


def main():
    print("=" * 70)
    print("PROTOCOL MIX VISUAL REDESIGN VERIFICATION & SCREENSHOT HARNESS")
    print("=" * 70)

    artifact_dir = Path("/home/kali/.gemini/antigravity-cli/brain/dda78f86-f898-4861-b275-943ce0509418")
    artifact_dir.mkdir(parents=True, exist_ok=True)

    port = find_free_port()
    settings = Settings(
        database_path=REPO_ROOT / "backend" / "data" / "aegis_gateway.sqlite3",
        report_dir=REPO_ROOT / "backend" / "reports",
        dataset_dir=REPO_ROOT / "backend" / "dataset",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)

    server = ServerThread(app, port=port)
    server.start()
    time.sleep(1.0)

    driver = setup_driver()
    base_url = f"http://127.0.0.1:{port}"

    try:
        # Step 1: Login
        print("[1/4] Authenticating as Admin...")
        driver.get(f"{base_url}/login")
        btn = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "btnQuickAdmin")))
        driver.execute_script("arguments[0].click();", btn)
        time.sleep(0.5)
        submit_btn = driver.find_element(By.ID, "loginSubmitBtn")
        driver.execute_script("arguments[0].click();", submit_btn)

        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "sec-topology")))
        time.sleep(1.5)

        # Step 2: Verify Protocol Mix Panel & Default Dominant State
        print("[2/4] Verifying Default Dominant Protocol Mix state...")
        topo_section = driver.find_element(By.ID, "sec-topology")
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'instant', block: 'center'});", topo_section)
        time.sleep(1.0)

        # Locate protocol donut panel (second panel in sec-topology)
        panels = driver.find_elements(By.CSS_SELECTOR, "#sec-topology .panel")
        assert len(panels) >= 2, "Expected at least 2 panels in sec-topology"
        proto_panel = panels[1]

        # Verify Center HUD elements exist
        caption_el = driver.find_element(By.ID, "donutCenterCaption")
        proto_el = driver.find_element(By.ID, "donutPrimaryProto")
        pct_el = driver.find_element(By.ID, "donutPrimaryPct")
        pkts_el = driver.find_element(By.ID, "donutPrimaryPkts")
        badge_el = driver.find_element(By.ID, "protocolMixBadge")

        print(f"  Center HUD Caption: '{caption_el.text}'")
        print(f"  Center HUD Dominant Protocol: '{proto_el.text}'")
        print(f"  Center HUD Dominant Pct: '{pct_el.text}'")
        print(f"  Center HUD Dominant Pkts: '{pkts_el.text}'")
        print(f"  Dynamic Distribution Badge: '{badge_el.text}'")

        assert caption_el.text in ("DOMINANT", "UDP", "TCP"), f"Unexpected caption: {caption_el.text}"
        assert len(proto_el.text) > 0, "Dominant protocol text is empty"
        assert "%" in pct_el.text, "Dominant percentage does not contain '%'"
        assert "pkts" in pkts_el.text, "Dominant packets does not contain 'pkts'"
        assert badge_el.text == "UDP-Dominant", f"Expected 'UDP-Dominant', got '{badge_el.text}'"

        # Verify all 4 legend pills and their aligned metrics
        for proto in ["UDP", "TCP", "ICMP", "MQTT"]:
            row = driver.find_element(By.ID, f"protoRow{proto}")
            assert row.is_displayed(), f"Row for {proto} is not displayed"
            pkts = driver.find_element(By.ID, f"protoPkts{proto}").text
            pct = driver.find_element(By.ID, f"protoCount{proto}").text
            print(f"  Legend [{proto}]: {pkts} | {pct}")
            assert "pkts" in pkts, f"Expected 'pkts' in {pkts}"
            assert "%" in pct, f"Expected '%' in {pct}"

        # Capture Default State screenshots
        proto_panel.screenshot(str(artifact_dir / "protocol_mix_panel_dominant.png"))
        donut_box = driver.find_element(By.CLASS_NAME, "donut-chart-box")
        donut_box.screenshot(str(artifact_dir / "protocol_mix_donut_dominant.png"))
        print("  Saved protocol_mix_panel_dominant.png and protocol_mix_donut_dominant.png")

        # Step 3: Test Interactive Hover Interaction on Legend Row
        print("[3/4] Testing Interactive Hover on Legend Row (TCP)...")
        tcp_row = driver.find_element(By.ID, "protoRowTCP")
        actions = ActionChains(driver)
        actions.move_to_element(tcp_row).perform()
        time.sleep(0.5)

        # Inspect updated Center HUD
        hover_caption = driver.find_element(By.ID, "donutCenterCaption").text
        hover_proto = driver.find_element(By.ID, "donutPrimaryProto").text
        hover_pct = driver.find_element(By.ID, "donutPrimaryPct").text
        hover_pkts = driver.find_element(By.ID, "donutPrimaryPkts").text
        print(f"  Hover State: Caption='{hover_caption}', Proto='{hover_proto}', Pct='{hover_pct}', Pkts='{hover_pkts}'")
        assert hover_caption == "INSPECTING", f"Expected 'INSPECTING', got '{hover_caption}'"
        assert hover_proto == "TCP", f"Expected 'TCP', got '{hover_proto}'"

        # Capture Hovered State screenshots
        proto_panel.screenshot(str(artifact_dir / "protocol_mix_panel_hover_tcp.png"))
        donut_box.screenshot(str(artifact_dir / "protocol_mix_donut_hover_tcp.png"))
        print("  Saved protocol_mix_panel_hover_tcp.png and protocol_mix_donut_hover_tcp.png")

        # Step 4: Move mouse away and verify restoration
        print("[4/5] Verifying Hover Exit and restoration to Dominant...")
        actions.move_to_element(topo_section).perform()
        time.sleep(0.5)
        restored_caption = driver.find_element(By.ID, "donutCenterCaption").text
        print(f"  Restored Caption: '{restored_caption}'")
        assert restored_caption == "DOMINANT", f"Expected 'DOMINANT', got '{restored_caption}'"

        # Step 5: Test Dynamic Classification Badge under Diversified and Balanced Distributions
        print("[5/5] Testing Dynamic Badge: 'Diversified' and 'Balanced' states...")
        # 1. Diversified (e.g. UDP 50%, TCP 25%, ICMP 15%, MQTT 10%)
        badge_diversified = driver.execute_script("""
            const canvas = document.getElementById('protocolDonutChart');
            renderProtocolDonut(canvas, { mix: { 'UDP': 50, 'TCP': 25, 'ICMP': 15, 'MQTT': 10 } });
            return document.getElementById('protocolMixBadge').textContent;
        """)
        print(f"  Distribution Badge (50/25/15/10): '{badge_diversified}'")
        assert badge_diversified == "Diversified", f"Expected 'Diversified', got '{badge_diversified}'"
        proto_panel.screenshot(str(artifact_dir / "protocol_mix_badge_diversified.png"))

        # 2. Balanced (e.g. UDP 30%, TCP 28%, ICMP 22%, MQTT 20%)
        badge_balanced = driver.execute_script("""
            const canvas = document.getElementById('protocolDonutChart');
            renderProtocolDonut(canvas, { mix: { 'UDP': 30, 'TCP': 28, 'ICMP': 22, 'MQTT': 20 } });
            return document.getElementById('protocolMixBadge').textContent;
        """)
        print(f"  Distribution Badge (30/28/22/20): '{badge_balanced}'")
        assert badge_balanced == "Balanced", f"Expected 'Balanced', got '{badge_balanced}'"
        proto_panel.screenshot(str(artifact_dir / "protocol_mix_badge_balanced.png"))

        # 3. Restore to actual backend data
        driver.execute_script("""
            fetch('/api/protocols', { cache: 'no-store' })
                .then(r => r.json())
                .then(d => renderProtocolDonut(document.getElementById('protocolDonutChart'), d));
        """)
        time.sleep(0.5)
        badge_restored = driver.find_element(By.ID, "protocolMixBadge").text
        print(f"  Restored Badge (live backend): '{badge_restored}'")

        # Check browser console logs for any errors
        logs = driver.get_log("browser")
        severe_errors = [l for l in logs if l.get("level") == "SEVERE"]
        if severe_errors:
            print(f"  Browser Warnings/Errors: {severe_errors}")
        else:
            print("  Zero severe browser console errors detected.")

        print("=" * 70)
        print("ALL PROTOCOL MIX VERIFICATIONS COMPLETED SUCCESSFULLY!")
        print("=" * 70)

    finally:
        driver.quit()
        server.shutdown()


if __name__ == "__main__":
    main()
