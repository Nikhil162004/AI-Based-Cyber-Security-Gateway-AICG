#!/usr/bin/env python3
"""Responsive verification script for OT Network Topology panel across multiple viewports."""

import json
import os
import socket
import sys
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

ARTIFACT_DIR = Path("/home/kali/.gemini/antigravity-cli/brain/dda78f86-f898-4861-b275-943ce0509418")


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


def run_checks():
    settings = Settings()
    runtime = GatewayRuntime(settings=settings)
    app = create_app(runtime=runtime)
    port = find_free_port()
    server = ServerThread(app, port=port)
    server.start()

    driver = setup_driver()
    viewports = [
        (1600, 1000, "1600x1000"),
        (1366, 768, "1366x768"),
        (1280, 900, "1280x900"),
        (1024, 768, "1024x768"),
    ]

    results = {}

    try:
        url = f"http://127.0.0.1:{port}"
        print(f"Loading {url}/login...")
        driver.get(f"{url}/login")
        btn = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "btnQuickAdmin")))
        driver.execute_script("arguments[0].click();", btn)
        time.sleep(0.5)
        submit_btn = driver.find_element(By.ID, "loginSubmitBtn")
        driver.execute_script("arguments[0].click();", submit_btn)

        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "sec-topology"))
        )
        time.sleep(1.5)

        for width, height, label in viewports:
            print(f"\n--- Testing Viewport {label} ({width}x{height}) ---")
            driver.set_window_size(width, height)
            time.sleep(1.0)

            # Scroll into view
            panel = driver.find_element(By.CSS_SELECTOR, "#sec-topology .panel:first-child")
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", panel)
            time.sleep(0.5)

            # Measure geometry
            check_script = """
            const panel = document.querySelector('#sec-topology .panel:first-child');
            const strip = document.getElementById('topologyTelemetryStrip');
            const legend = document.querySelector('.mimic-legend');
            const disclaimer = document.querySelector('.topology-disclaimer');
            const pills = Array.from(strip.querySelectorAll('.telemetry-pill'));
            const indicators = Array.from(legend.querySelectorAll('.node-indicator'));

            const panelRect = panel.getBoundingClientRect();
            const stripRect = strip.getBoundingClientRect();
            const legendRect = legend.getBoundingClientRect();
            const disclaimerRect = disclaimer.getBoundingClientRect();

            // Check if strip and legend are inside panel bounds
            const stripOverflow = stripRect.right > (panelRect.right + 2);
            const legendOverflow = legendRect.right > (panelRect.right + 2);

            // Check pills visibility
            const pillsInfo = pills.map(p => {
                const r = p.getBoundingClientRect();
                return {
                    text: p.innerText.trim(),
                    visible: (r.width > 0 && r.height > 0 && r.right <= panelRect.right + 2)
                };
            });

            // Check indicators visibility
            const indicatorsInfo = indicators.map(ind => {
                const r = ind.getBoundingClientRect();
                return {
                    text: ind.innerText.trim(),
                    visible: (r.width > 0 && r.height > 0 && r.right <= panelRect.right + 2)
                };
            });

            return {
                panelWidth: panelRect.width,
                panelHeight: panelRect.height,
                stripWidth: stripRect.width,
                stripHeight: stripRect.height,
                stripOverflow: stripOverflow,
                legendWidth: legendRect.width,
                legendHeight: legendRect.height,
                legendOverflow: legendOverflow,
                disclaimerWidth: disclaimerRect.width,
                disclaimerRight: disclaimerRect.right,
                disclaimerOverflow: disclaimerRect.right > (panelRect.right + 2),
                pills: pillsInfo,
                indicators: indicatorsInfo,
                allPillsVisible: pillsInfo.every(p => p.visible),
                allIndicatorsVisible: indicatorsInfo.every(ind => ind.visible)
            };
            """
            data = driver.execute_script(check_script)
            results[label] = data

            print(f"Panel Width: {data['panelWidth']:.1f}px, Height: {data['panelHeight']:.1f}px")
            print(f"Telemetry Strip: {data['stripWidth']:.1f}px x {data['stripHeight']:.1f}px, Overflow: {data['stripOverflow']}")
            print(f"All 5 Telemetry Pills Visible without clipping: {data['allPillsVisible']}")
            for p in data['pills']:
                print(f"  - {p['text']}: visible={p['visible']}")
            print(f"Legend: {data['legendWidth']:.1f}px x {data['legendHeight']:.1f}px, Overflow: {data['legendOverflow']}")
            print(f"All 4 Legend Indicators Visible: {data['allIndicatorsVisible']}")
            print(f"Disclaimer Overflow: {data['disclaimerOverflow']}")

            assert not data['stripOverflow'], f"Strip overflows panel at {label}!"
            assert not data['legendOverflow'], f"Legend overflows panel at {label}!"
            assert not data['disclaimerOverflow'], f"Disclaimer overflows panel at {label}!"
            assert data['allPillsVisible'], f"Some pills are clipped at {label}!"
            assert data['allIndicatorsVisible'], f"Some indicators are clipped at {label}!"

            # Take screenshot of the topology panel
            screenshot_path = ARTIFACT_DIR / f"topology_responsive_{label}.png"
            panel.screenshot(str(screenshot_path))
            print(f"Saved screenshot: {screenshot_path}")

        print("\nAll responsive viewport verification tests PASSED successfully!")
        return results

    finally:
        driver.quit()
        server.shutdown()


if __name__ == "__main__":
    run_checks()
