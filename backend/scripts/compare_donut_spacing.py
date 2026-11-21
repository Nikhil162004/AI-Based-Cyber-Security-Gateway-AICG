#!/usr/bin/env python3
"""Compare spacing configurations for enlarged donut and protocol legend."""

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
import socket, threading, time
from werkzeug.serving import make_server
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def main():
    port = find_free_port()
    server = make_server("127.0.0.1", port, create_app(GatewayRuntime(Settings())), threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    opts = Options()
    opts.binary_location = "/usr/bin/chromium"
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--window-size=1600,1050")
    driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=opts)
    
    try:
        driver.get(f"http://127.0.0.1:{port}/login")
        btn = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "btnQuickAdmin")))
        driver.execute_script("arguments[0].click();", btn)
        driver.execute_script("arguments[0].click();", driver.find_element(By.ID, "loginSubmitBtn"))
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "sec-topology")))
        time.sleep(1)

        topo = driver.find_element(By.ID, "sec-topology")
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", topo)
        time.sleep(0.5)

        panels = driver.find_elements(By.CSS_SELECTOR, "#sec-topology .panel")
        proto_panel = panels[1]

        configs = [
            ("gap_28", "wrap.style.justifyContent = 'flex-start'; wrap.style.gap = '28px'; wrap.style.padding = '14px 16px 20px';"),
            ("gap_36", "wrap.style.justifyContent = 'flex-start'; wrap.style.gap = '36px'; wrap.style.padding = '14px 16px 20px';"),
            ("gap_48", "wrap.style.justifyContent = 'flex-start'; wrap.style.gap = '48px'; wrap.style.padding = '14px 16px 20px';"),
            ("space_around", "wrap.style.justifyContent = 'space-around'; wrap.style.gap = '16px'; wrap.style.padding = '14px 16px 16px';")
        ]

        for name, js in configs:
            driver.execute_script(f"""
            const wrap = document.querySelector(".donut-stage-wrap");
            {js}
            """)
            time.sleep(0.3)
            screenshot_path = f"/home/kali/.gemini/antigravity-cli/brain/dda78f86-f898-4861-b275-943ce0509418/test_spacing_{name}.png"
            proto_panel.screenshot(screenshot_path)
            
            metrics = driver.execute_script("""
            const chart = document.querySelector(".donut-chart-box");
            const pills = document.querySelector(".protocol-pills-list");
            const wrap = document.querySelector(".donut-stage-wrap");
            const c = chart.getBoundingClientRect();
            const l = pills.getBoundingClientRect();
            const w = wrap.getBoundingClientRect();
            return {
                gap: l.top - c.bottom,
                bottomSpace: w.bottom - l.bottom,
                topSpace: c.top - w.top,
                panelHeight: wrap.getBoundingClientRect().height
            };
            """)
            print(f"{name}: gap={metrics['gap']:.1f}px, bottomSpace={metrics['bottomSpace']:.1f}px, topSpace={metrics['topSpace']:.1f}px")

    finally:
        driver.quit()
        server.shutdown()

if __name__ == "__main__":
    main()
