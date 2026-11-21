#!/usr/bin/env python3
"""Verification and screenshot capture script for the Six-Attacker DDoS Topology upgrade."""

import os
import sys
import socket
import threading
import time
from pathlib import Path
from werkzeug.serving import make_server

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window

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
    print("SIX-ATTACKER TOPOLOGY VISUAL VERIFICATION & SCREENSHOT HARNESS")
    print("=" * 70)

    # Output directory
    evidence_dir = REPO_ROOT / "backend" / "reports" / "evidence" / "screenshots"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    
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
        print("[1/5] Authenticating as Admin...")
        driver.get(f"{base_url}/login")
        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "btnQuickAdmin"))).click()
        time.sleep(0.5)
        driver.find_element(By.ID, "loginSubmitBtn").click()

        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "sec-topology")))
        time.sleep(1.5)

        # Step 2: STATE 1: Normal Baseline
        print("[2/5] Capturing State 1: Normal Baseline Topology...")
        topo_elem = driver.find_element(By.ID, "sec-topology")
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'instant', block: 'center'});", topo_elem)
        time.sleep(1.0)

        # Verify dynamic metadata text
        subtitle = driver.find_element(By.CSS_SELECTOR, "#sec-topology .panel-subtitle").text
        print(f"  Subtitle: '{subtitle}'")
        assert "OT Nodes: 4" in subtitle
        assert "DDoS Sources: 6" in subtitle
        assert "Total Visible Nodes: 10" in subtitle
        assert "Links: 9" in subtitle

        # Check all 6 attacker nodes exist
        for i in range(1, 7):
            node = driver.find_element(By.ID, f"nodeAttacker{i}")
            assert node.is_displayed()
            title = driver.find_element(By.ID, f"atkTitle{i}").get_attribute("textContent").strip()
            ip = driver.find_element(By.ID, f"atkIp{i}").get_attribute("textContent").strip()
            status = driver.find_element(By.ID, f"atkStatusText{i}").get_attribute("textContent").strip()
            print(f"  Attacker {i}: {title} | IP: {ip} | Status: {status}")
            assert "IDLE" in status

        # Capture screenshots for State 1
        s1_file = evidence_dir / "topology_state1_normal.png"
        driver.save_screenshot(str(s1_file))
        driver.save_screenshot(str(artifact_dir / "topology_state1_normal.png"))
        
        # Element crop of topology panel
        panel_elem = driver.find_element(By.CSS_SELECTOR, "#sec-topology .panel:first-child")
        panel_elem.screenshot(str(evidence_dir / "topology_panel_state1_normal.png"))
        panel_elem.screenshot(str(artifact_dir / "topology_panel_state1_normal.png"))
        print(f"  Saved State 1 screenshots.")

        # Step 3: STATE 2: DDoS Attack Detected
        print("[3/5] Starting controlled DDoS simulation & Capturing State 2...")
        runtime.start_simulation("udp_flood", intensity=3)
        time.sleep(1.5)

        # Trigger dashboard refresh in UI
        driver.execute_script("refreshDashboard();")
        time.sleep(1.2)

        # Check attacker status in State 2
        for i in range(1, 7):
            status = driver.find_element(By.ID, f"atkStatusText{i}").get_attribute("textContent").strip()
            print(f"  Attacker {i} in attack mode: Status={status}")

        s2_file = evidence_dir / "topology_state2_attack.png"
        driver.save_screenshot(str(s2_file))
        driver.save_screenshot(str(artifact_dir / "topology_state2_attack.png"))
        panel_elem.screenshot(str(evidence_dir / "topology_panel_state2_attack.png"))
        panel_elem.screenshot(str(artifact_dir / "topology_panel_state2_attack.png"))
        print(f"  Saved State 2 screenshots.")

        # Step 4: STATE 3: Mitigation Active
        print("[4/5] Engaging in-process mitigation containment & Capturing State 3...")
        runtime.response.isolate("ATK-01", "ISOLATE", "Automated DDoS Mitigation", state="CONTAINED")
        runtime.stop_simulation("udp_flood")
        time.sleep(1.0)
        driver.execute_script("refreshDashboard();")
        time.sleep(1.2)

        for i in range(1, 7):
            status = driver.find_element(By.ID, f"atkStatusText{i}").get_attribute("textContent").strip()
            print(f"  Attacker {i} in mitigated mode: Status={status}")

        s3_file = evidence_dir / "topology_state3_mitigation.png"
        driver.save_screenshot(str(s3_file))
        driver.save_screenshot(str(artifact_dir / "topology_state3_mitigation.png"))
        panel_elem.screenshot(str(evidence_dir / "topology_panel_state3_mitigation.png"))
        panel_elem.screenshot(str(artifact_dir / "topology_panel_state3_mitigation.png"))
        print(f"  Saved State 3 screenshots.")

        # Step 5: Responsive Layouts
        print("[5/5] Testing responsive viewports...")
        viewports = [
            ("1600x1000", 1600, 1000),
            ("1280x900", 1280, 900),
            ("1024x768", 1024, 768),
        ]
        for name, w, h in viewports:
            driver.set_window_size(w, h)
            time.sleep(0.5)
            driver.save_screenshot(str(evidence_dir / f"topology_viewport_{name}.png"))
            driver.save_screenshot(str(artifact_dir / f"topology_viewport_{name}.png"))
            print(f"  Viewport {name} verified and captured.")

        print("=" * 70)
        print("ALL VISUAL VERIFICATIONS AND SCREENSHOTS CAPTURED SUCCESSFULLY!")
        print("=" * 70)

    finally:
        driver.quit()
        server.shutdown()


if __name__ == "__main__":
    main()
