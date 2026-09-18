/* ==========================================================================
   AICG • INDUSTRIAL SOC & OT SECURITY OPERATIONS HMI
   AI-Based Cyber Security Gateway for Industry 4.0
   Client Runtime, Zero-Dependency Canvas Visualizations, SSE Integration
   ========================================================================== */

const startTimeMonotonic = Date.now();
window.currentAutoResponse = true;

/* ==========================================================================
   1. TIME & UPTIME UTILITY
   ========================================================================== */
function updateClockAndUptime() {
    const clockEl = document.getElementById("liveClock");
    const uptimeEl = document.getElementById("liveUptime");
    
    const now = new Date();
    const utcStr = now.toUTCString().split(" ")[4] + " UTC";
    if (clockEl) clockEl.textContent = utcStr;
    
    const elapsedSec = Math.floor((Date.now() - startTimeMonotonic) / 1000);
    const hrs = String(Math.floor(elapsedSec / 3600)).padStart(2, "0");
    const mins = String(Math.floor((elapsedSec % 3600) / 60)).padStart(2, "0");
    const secs = String(elapsedSec % 60).padStart(2, "0");
    if (uptimeEl) uptimeEl.textContent = `UPTIME: ${hrs}h ${mins}m ${secs}s`;
}
setInterval(updateClockAndUptime, 1000);
updateClockAndUptime();


/* ==========================================================================
   2. TOP KPI STRIP & STATUS SUMMARY
   ========================================================================== */
function updateSummary(summary, fullStatus) {
    if (!summary || typeof summary !== "object") return;

    const pred = summary.latest_prediction || "NORMAL";
    const isAttack = pred === "ATTACK";
    const activeInc = summary.active_incident;
    const hasActiveIncident = Boolean(activeInc && !["RESOLVED", "CLOSED"].includes(activeInc.lifecycle_state));
    const activeState = hasActiveIncident ? String(activeInc.lifecycle_state).toUpperCase() : null;
    const isThreatActive = isAttack || hasActiveIncident;
    const ddosProb = Number(summary.latest_ddos_probability ?? (isAttack ? 0.99 : 0.05));
    const pps = Number(summary.latest_packet_rate ?? 18.0);
    const byteRate = Number(summary.latest_bytes_per_second ?? 4140.0);
    const secAction = summary.latest_security_action || (isAttack ? "BLOCK" : (isThreatActive ? "ALERT" : "MONITOR"));
    const mitAction = isThreatActive ? (summary.latest_mitigation_action || (isAttack ? "BLOCK" : "NONE")) : "NONE";
    const trustScore = Number(summary.trust_score ?? (isAttack ? 15.0 : 100.0));

    // Card 1: Throughput
    const packetRateEl = document.getElementById("packetRate");
    const throughputEl = document.getElementById("throughput");
    const rateStatusTag = document.getElementById("rateStatusTag");
    if (packetRateEl) packetRateEl.textContent = pps.toFixed(1);
    if (throughputEl) throughputEl.textContent = (byteRate / 1024).toFixed(2);
    if (rateStatusTag) {
        rateStatusTag.textContent = pps > 60 ? "HIGH LOAD" : "NORMAL";
        rateStatusTag.className = `kpi-status-tag ${pps > 60 ? "tag-red" : "tag-blue"}`;
    }

    // Card 2: DDoS Risk Index
    const ddosProbEl = document.getElementById("ddosProbability");
    const threatStatusEl = document.getElementById("threatStatus");
    const threatMetaEl = document.getElementById("threatMeta");
    const classificationEl = document.getElementById("classification");
    const kpiRiskTag = document.getElementById("kpiRiskTag");
    const headerThreatPill = document.getElementById("headerThreatPill");

    const pctStr = `${(ddosProb * 100).toFixed(1)}%`;
    if (ddosProbEl) ddosProbEl.textContent = pctStr;
    if (classificationEl) classificationEl.textContent = pred;

    if (threatStatusEl) {
        threatStatusEl.textContent = isAttack ? "ATTACK" : (hasActiveIncident ? activeState : "CLEAR");
        threatStatusEl.style.color = isThreatActive ? (isAttack ? "var(--red)" : "var(--amber)") : "var(--green)";
    }
    if (threatMetaEl) {
        threatMetaEl.textContent = isAttack
            ? "DDoS Attack Vector Active"
            : (hasActiveIncident ? `Incident ${activeInc.incident_id} (${activeState})` : "Baseline Normal");
    }
    if (kpiRiskTag) {
        kpiRiskTag.textContent = isAttack ? "CRITICAL" : (hasActiveIncident ? activeState : "CLEAR");
        kpiRiskTag.className = `kpi-status-tag ${isAttack ? "tag-red" : (hasActiveIncident ? "tag-amber" : "tag-green")}`;
    }
    if (headerThreatPill) {
        headerThreatPill.className = `threat-state-pill ${isAttack ? "attack" : (hasActiveIncident ? "recovering" : "clear")}`;
        headerThreatPill.textContent = isAttack ? "ATTACK ACTIVE" : (hasActiveIncident ? `THREAT ${activeState}` : "SYSTEM SECURE");
    }

    // Card 3: Plant State
    const plantStateVal = document.getElementById("plantStateVal");
    if (plantStateVal) {
        plantStateVal.textContent = isAttack ? "ATTACKED" : (hasActiveIncident ? activeState : "CLEAR");
        plantStateVal.style.color = isThreatActive ? (isAttack ? "var(--red)" : "var(--amber)") : "var(--green)";
    }

    // Card 4: Mitigation State
    const securityActionEl = document.getElementById("securityAction");
    const mitigationActionEl = document.getElementById("mitigationAction");
    const mitModeTag = document.getElementById("mitigationModeTag");
    const respPolicyEl = document.getElementById("respPolicyMode");
    const btnRespEl = document.getElementById("btnResponseModeText");

    if (securityActionEl) securityActionEl.textContent = secAction;
    if (mitigationActionEl) {
        mitigationActionEl.textContent = mitAction;
        mitigationActionEl.style.color = isThreatActive ? "var(--red)" : "var(--cyan)";
    }
    if (fullStatus) {
        const mode = (fullStatus.response_mode || "DRY_RUN").replace(/_/g, "-");
        if (mitModeTag) mitModeTag.textContent = mode;
        if (respPolicyEl) respPolicyEl.textContent = `${fullStatus.auto_response ? "AUTO" : "MANUAL"} (${fullStatus.response_mode || "DRY_RUN"})`;
        if (btnRespEl) btnRespEl.textContent = fullStatus.auto_response ? "AUTO: ON" : "MANUAL: ON";
    }

    // Security Status Banner
    updateStatusBanner(pred, ddosProb, summary);

    // Circular Percentage Gauges
    updateCircularGauges(ddosProb, trustScore);
}

function updateStatusBanner(prediction, ddosProb, summary) {
    const banner = document.getElementById("securityStatusBanner");
    const badge = document.getElementById("bannerIconBadge");
    const headline = document.getElementById("bannerHeadline");
    const detail = document.getElementById("bannerDetail");
    const target = document.getElementById("bannerTarget");
    const severity = document.getElementById("severity");

    if (!banner || !headline) return;

    const isAttack = prediction === "ATTACK";
    const activeInc = summary.active_incident;
    const hasActiveIncident = Boolean(activeInc && !["RESOLVED", "CLOSED"].includes(activeInc.lifecycle_state));
    const activeState = hasActiveIncident ? String(activeInc.lifecycle_state).toUpperCase() : (summary.lifecycle_state || "NORMAL");
    const isRecovering = activeState === "RECOVERING" || summary.lifecycle_state === "RECOVERING";

    if (isAttack) {
        banner.className = "security-status-banner banner-threat";
        if (badge) badge.textContent = "⚠️";
        const atkType = summary.attack_type || (summary.latest && summary.latest.attack_type) || "UDP_FLOOD";
        headline.textContent = `IDENTIFIED • ${String(atkType).toUpperCase()} • ATTACK SOURCE 10.42.0.250 → GATEWAY`;
        if (detail) detail.textContent = "Abnormal packet exhaustion surge detected. Software containment active in dry-run mode.";
        if (target) target.textContent = "GATEWAY-01 (10.42.0.1:5683)";
        if (severity) {
            severity.textContent = summary.severity || "CRITICAL";
            severity.style.color = "var(--red)";
        }
    } else if (isRecovering) {
        banner.className = "security-status-banner banner-recovering";
        if (badge) badge.textContent = "🔄";
        headline.textContent = "RECOVERING • TRAFFIC RETURNING TO BASELINE • VERIFYING STREAK";
        if (detail) detail.textContent = "Telemetry within normal bounds. Awaiting consecutive normal verification windows.";
        if (target) target.textContent = (activeInc && activeInc.incident_id) || "GATEWAY-01";
        if (severity) {
            severity.textContent = "MEDIUM";
            severity.style.color = "var(--amber)";
        }
    } else if (hasActiveIncident) {
        banner.className = "security-status-banner banner-recovering";
        if (badge) badge.textContent = "🛡️";
        headline.textContent = `CONTAINED • ${activeState} • OBSERVING BASELINE TELEMETRY`;
        if (detail) detail.textContent = "Simulated software mitigation active. Observing device baseline for qualification.";
        if (target) target.textContent = (activeInc && activeInc.incident_id) || "GATEWAY-01";
        if (severity) {
            severity.textContent = activeInc.severity || "HIGH";
            severity.style.color = "var(--amber)";
        }
    } else {
        banner.className = "security-status-banner";
        if (badge) badge.textContent = "✓";
        headline.textContent = "CLEAR • NO ACTIVE DDOS ANOMALY • PLANT WITHIN BASELINE";
        if (detail) detail.textContent = "Baseline sensor telemetry active across 6LoWPAN mesh. In-process defense pipeline armed.";
        if (target) target.textContent = "GATEWAY (10.42.0.1)";
        if (severity) {
            severity.textContent = "INFO";
            severity.style.color = "var(--green)";
        }
    }
}

function updateCircularGauges(threatProb, trustScore) {
    const circumference = 213.62;

    // 1. AI Threat Confidence Gauge
    const threatCircle = document.getElementById("aiThreatGaugeCircle");
    const threatText = document.getElementById("aiThreatGaugeText");
    if (threatCircle && threatText) {
        const clampedThreat = Math.min(1, Math.max(0, threatProb));
        const offset = circumference - (circumference * clampedThreat);
        threatCircle.style.strokeDashoffset = offset;
        threatText.textContent = `${(clampedThreat * 100).toFixed(0)}%`;
        if (clampedThreat > 0.6) {
            threatCircle.setAttribute("class", "gauge-progress gauge-threat-progress high");
            threatText.style.color = "var(--red)";
        } else if (clampedThreat > 0.25) {
            threatCircle.setAttribute("class", "gauge-progress gauge-threat-progress mid");
            threatText.style.color = "var(--amber)";
        } else {
            threatCircle.setAttribute("class", "gauge-progress gauge-threat-progress");
            threatText.style.color = "var(--cyan)";
        }
    }

    // 2. Trust Posture Gauge
    const trustCircle = document.getElementById("trustGaugeCircle");
    const trustText = document.getElementById("trustGaugeText");
    if (trustCircle && trustText) {
        const clampedTrust = Math.min(100, Math.max(0, trustScore));
        const normTrust = clampedTrust / 100;
        const offset = circumference - (circumference * normTrust);
        trustCircle.style.strokeDashoffset = offset;
        trustText.textContent = `${clampedTrust.toFixed(0)}`;
        if (clampedTrust >= 70) {
            trustCircle.setAttribute("class", "gauge-progress gauge-trust-progress");
            trustText.style.color = "var(--green)";
        } else if (clampedTrust >= 40) {
            trustCircle.setAttribute("class", "gauge-progress gauge-trust-progress mid");
            trustText.style.color = "var(--amber)";
        } else {
            trustCircle.setAttribute("class", "gauge-progress gauge-trust-progress low");
            trustText.style.color = "var(--red)";
        }
    }
}


/* ==========================================================================
   3. OFFLINE-SAFE NATIVE CANVAS VISUALIZATIONS (EXACTLY TWO TIME-SERIES)
   ========================================================================== */

/**
 * Setup a high-DPI canvas context for razor-sharp rendering.
 */
function setupCanvas(canvas) {
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const parent = canvas.parentElement;
    const width = Math.max(20, Math.floor(rect.width || canvas.clientWidth || (parent ? parent.clientWidth : 300)));
    const height = Math.max(20, Math.floor(rect.height || canvas.clientHeight || (parent ? parent.clientHeight : 150)));

    const targetW = Math.round(width * dpr);
    const targetH = Math.round(height * dpr);

    if (canvas.width !== targetW || canvas.height !== targetH) {
        canvas.width = targetW;
        canvas.height = targetH;
    }
    const ctx = canvas.getContext("2d");
    if (ctx.setTransform) {
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    } else {
        ctx.resetTransform();
        ctx.scale(dpr, dpr);
    }
    return { ctx, width, height };
}

/**
 * Primary Chart #1: Historian • Live OT Network Traffic (Packets / Second)
 * Displays continuous legitimate OT baseline (~18 pps) vs live traffic vs attack surge
 */
function renderHistorianChart(canvas, rows) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padLeft = 45;
    const padRight = 15;
    const padTop = 18;
    const padBottom = 25;
    const chartW = width - padLeft - padRight;
    const chartH = height - padTop - padBottom;

    const dataPoints = (rows && rows.length) ? rows.slice(-30) : [];
    if (!dataPoints.length) {
        ctx.fillStyle = "#64748b";
        ctx.font = "11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Awaiting live OT telemetry windows...", width / 2, height / 2);
        return;
    }

    const rates = dataPoints.map(r => Number(r.packets_per_second || r.packet_rate || 0));
    const maxVal = Math.max(60, ...rates) * 1.15;
    const baselinePps = 18.0;

    // Draw Grid Lines & Y-Axis Labels
    ctx.strokeStyle = "rgba(70, 100, 140, 0.18)";
    ctx.lineWidth = 1;
    ctx.fillStyle = "#7890a8";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";

    const ySteps = 4;
    for (let i = 0; i <= ySteps; i++) {
        const yVal = (maxVal / ySteps) * i;
        const yPos = padTop + chartH - (i / ySteps) * chartH;
        ctx.beginPath();
        ctx.moveTo(padLeft, yPos);
        ctx.lineTo(padLeft + chartW, yPos);
        ctx.stroke();
        ctx.fillText(yVal.toFixed(0), padLeft - 6, yPos + 3);
    }

    const xStep = chartW / Math.max(1, dataPoints.length - 1);

    // 1. Draw Legitimate OT Baseline Band (15-20 pps shaded zone)
    const baseBandTopY = padTop + chartH - (20.0 / maxVal) * chartH;
    const baseBandBottomY = padTop + chartH - (14.0 / maxVal) * chartH;
    ctx.fillStyle = "rgba(16, 185, 129, 0.08)";
    ctx.fillRect(padLeft, baseBandTopY, chartW, baseBandBottomY - baseBandTopY);

    // 2. Draw Legitimate Baseline Line (~18 pps dashed green)
    const baseYPos = padTop + chartH - (baselinePps / maxVal) * chartH;
    ctx.save();
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = "#10b981";
    ctx.lineWidth = 1.4;
    ctx.moveTo(padLeft, baseYPos);
    ctx.lineTo(padLeft + chartW, baseYPos);
    ctx.stroke();
    ctx.fillStyle = "#10b981";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.textAlign = "left";
    ctx.fillText("Normal OT Baseline (~18 pps)", padLeft + 6, baseYPos - 4);
    ctx.restore();

    // 3. Check for Attack Surge condition
    const hasAttackSurge = rates.some(r => r > 30.0);

    // 4. Draw Area Fill Under Live Traffic
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const val = Number(r.packets_per_second || r.packet_rate || 0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + (dataPoints.length - 1) * xStep, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();

    const areaGrad = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
    if (hasAttackSurge) {
        areaGrad.addColorStop(0, "rgba(244, 63, 94, 0.32)");
        areaGrad.addColorStop(0.6, "rgba(56, 189, 248, 0.12)");
        areaGrad.addColorStop(1, "rgba(16, 185, 129, 0.04)");
    } else {
        areaGrad.addColorStop(0, "rgba(56, 189, 248, 0.22)");
        areaGrad.addColorStop(1, "rgba(56, 189, 248, 0.02)");
    }
    ctx.fillStyle = areaGrad;
    ctx.fill();

    // 5. Draw Live Traffic Curve
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const val = Number(r.packets_per_second || r.packet_rate || 0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = hasAttackSurge ? "#f43f5e" : "#38bdf8";
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // 6. Draw Data Points (color-coded by rate)
    dataPoints.forEach((r, idx) => {
        const val = Number(r.packets_per_second || r.packet_rate || 0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        const isSpike = val > 30.0;
        ctx.beginPath();
        ctx.arc(x, y, isSpike ? 3.5 : 2, 0, Math.PI * 2);
        ctx.fillStyle = isSpike ? "#f43f5e" : "#38bdf8";
        ctx.fill();
    });

    // 7. Draw Simulated Throttle Line if active (DRY_RUN)
    const hasThrottle = dataPoints.some(r => ["BLOCK", "RATE_LIMIT", "ISOLATE"].includes(r.security_action || r.mitigation_action || ""));
    if (hasThrottle) {
        ctx.save();
        ctx.beginPath();
        ctx.setLineDash([4, 4]);
        ctx.strokeStyle = "#f59e0b";
        ctx.lineWidth = 1.6;
        dataPoints.forEach((r, idx) => {
            const isMit = ["BLOCK", "RATE_LIMIT", "ISOLATE"].includes(r.security_action || r.mitigation_action || "");
            const raw = Number(r.packets_per_second || r.packet_rate || 0);
            const val = isMit ? Math.max(0, raw - baselinePps) : 0;
            const x = padLeft + idx * xStep;
            const y = padTop + chartH - (val / maxVal) * chartH;
            if (idx === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();
        ctx.restore();
    }

    // 8. Draw X-Axis Time Labels
    ctx.fillStyle = "#64748b";
    ctx.textAlign = "center";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    const labelStep = Math.max(1, Math.floor(dataPoints.length / 5));
    for (let i = 0; i < dataPoints.length; i += labelStep) {
        const ts = dataPoints[i].window_start || "";
        const label = ts.includes("T") ? ts.split("T")[1].split(".")[0] : ts.slice(-8);
        const x = padLeft + i * xStep;
        ctx.fillText(label, x, padTop + chartH + 16);
    }
}

/**
 * Primary Chart #2: Resource Impact • Modelled Power Dissipation (mW)
 * Derived software model: Nominal quiescent baseline (~55 mW) vs attack-induced resource dissipation
 */
function renderEnergyChart(canvas, rows) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padLeft = 45;
    const padRight = 15;
    const padTop = 18;
    const padBottom = 25;
    const chartW = width - padLeft - padRight;
    const chartH = height - padTop - padBottom;

    const dataPoints = (rows && rows.length) ? rows.slice(-30) : [];
    if (!dataPoints.length) {
        ctx.fillStyle = "#64748b";
        ctx.font = "11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Awaiting modelled power dissipation data...", width / 2, height / 2);
        return;
    }

    // Extract energy rate (mW), fallback to cause-based model formula if not present
    const energyVals = dataPoints.map(r => {
        if (r.energy_rate !== undefined && r.energy_rate !== null && Number(r.energy_rate) > 0) {
            return Number(r.energy_rate);
        }
        const pps = Number(r.packets_per_second || r.packet_rate || 18.0);
        return 50.0 + pps * 0.35 + 5.0;
    });

    const baselineVal = 55.0; // Quiescent baseline in mW
    const maxVal = Math.max(100.0, ...energyVals) * 1.15;

    // Draw Grid Lines & Y-Axis Labels (mW)
    ctx.strokeStyle = "rgba(70, 100, 140, 0.18)";
    ctx.lineWidth = 1;
    ctx.fillStyle = "#7890a8";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";

    const ySteps = 4;
    for (let i = 0; i <= ySteps; i++) {
        const yVal = (maxVal / ySteps) * i;
        const yPos = padTop + chartH - (i / ySteps) * chartH;
        ctx.beginPath();
        ctx.moveTo(padLeft, yPos);
        ctx.lineTo(padLeft + chartW, yPos);
        ctx.stroke();
        ctx.fillText(`${yVal.toFixed(0)} mW`, padLeft - 6, yPos + 3);
    }

    const xStep = chartW / Math.max(1, dataPoints.length - 1);

    // Draw Baseline Reference Line (55 mW dashed green)
    const baseNorm = Math.min(1, baselineVal / maxVal);
    const baseYPos = padTop + chartH - baseNorm * chartH;
    ctx.save();
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = "#10b981";
    ctx.lineWidth = 1.4;
    ctx.moveTo(padLeft, baseYPos);
    ctx.lineTo(padLeft + chartW, baseYPos);
    ctx.stroke();
    ctx.fillStyle = "#10b981";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.textAlign = "left";
    ctx.fillText("Nominal Baseline (55 mW)", padLeft + 6, baseYPos - 4);
    ctx.restore();

    // Draw Critical Saturation Line (110 mW dashed red) if within maxVal
    if (110.0 < maxVal) {
        const critYPos = padTop + chartH - (110.0 / maxVal) * chartH;
        ctx.save();
        ctx.beginPath();
        ctx.setLineDash([3, 3]);
        ctx.strokeStyle = "rgba(244, 63, 94, 0.7)";
        ctx.lineWidth = 1;
        ctx.moveTo(padLeft, critYPos);
        ctx.lineTo(padLeft + chartW, critYPos);
        ctx.stroke();
        ctx.fillStyle = "rgba(244, 63, 94, 0.85)";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";
        ctx.fillText("Saturation Threshold (110 mW)", padLeft + chartW - 6, critYPos - 4);
        ctx.restore();
    }

    // Draw Live Modelled Power Dissipation Area Fill
    ctx.beginPath();
    energyVals.forEach((val, idx) => {
        const norm = Math.min(1, Math.max(0, val / maxVal));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - norm * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + (dataPoints.length - 1) * xStep, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();

    const isHighEnergy = energyVals.some(v => v > 80.0);
    const grad = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
    if (isHighEnergy) {
        grad.addColorStop(0, "rgba(245, 158, 11, 0.35)");
        grad.addColorStop(0.7, "rgba(245, 158, 11, 0.1)");
        grad.addColorStop(1, "rgba(16, 185, 129, 0.03)");
    } else {
        grad.addColorStop(0, "rgba(16, 185, 129, 0.2)");
        grad.addColorStop(1, "rgba(16, 185, 129, 0.02)");
    }
    ctx.fillStyle = grad;
    ctx.fill();

    // Draw Live Modelled Power Dissipation Curve Line
    ctx.beginPath();
    energyVals.forEach((val, idx) => {
        const norm = Math.min(1, Math.max(0, val / maxVal));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - norm * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = isHighEnergy ? "#f59e0b" : "#10b981";
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // Draw points for each reading
    energyVals.forEach((val, idx) => {
        const norm = Math.min(1, Math.max(0, val / maxVal));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - norm * chartH;
        const isElevated = val > 75.0;
        ctx.beginPath();
        ctx.arc(x, y, isElevated ? 3.5 : 2, 0, Math.PI * 2);
        ctx.fillStyle = isElevated ? "#f43f5e" : "#f59e0b";
        ctx.fill();
    });

    // Draw X-Axis Time Labels
    ctx.fillStyle = "#64748b";
    ctx.textAlign = "center";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    const labelStep = Math.max(1, Math.floor(dataPoints.length / 5));
    for (let i = 0; i < dataPoints.length; i += labelStep) {
        const ts = dataPoints[i].window_start || "";
        const label = ts.includes("T") ? ts.split("T")[1].split(".")[0] : ts.slice(-8);
        const x = padLeft + i * xStep;
        ctx.fillText(label, x, padTop + chartH + 16);
    }
}

/**
 * Primary Chart #2: AI Threat • DDoS Probability Curve
 */
function renderThreatChart(canvas, rows) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padLeft = 40;
    const padRight = 15;
    const padTop = 15;
    const padBottom = 25;
    const chartW = width - padLeft - padRight;
    const chartH = height - padTop - padBottom;

    const dataPoints = (rows && rows.length) ? rows.slice(-30) : [];
    if (!dataPoints.length) {
        ctx.fillStyle = "#64748b";
        ctx.font = "11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Awaiting inference classifications...", width / 2, height / 2);
        return;
    }

    // Draw Grid Lines & Y-Axis Percentage Labels (0% to 100%)
    ctx.strokeStyle = "rgba(70, 100, 140, 0.18)";
    ctx.lineWidth = 1;
    ctx.fillStyle = "#7890a8";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";

    [0, 25, 50, 75, 100].forEach(pct => {
        const yPos = padTop + chartH - (pct / 100) * chartH;
        ctx.beginPath();
        ctx.moveTo(padLeft, yPos);
        ctx.lineTo(padLeft + chartW, yPos);
        ctx.stroke();
        ctx.fillText(`${pct}%`, padLeft - 6, yPos + 3);
    });

    const xStep = chartW / Math.max(1, dataPoints.length - 1);

    // Draw Mitigation Threshold Line (62% dashed)
    const thresholdY = padTop + chartH - (62 / 100) * chartH;
    ctx.beginPath();
    ctx.setLineDash([5, 4]);
    ctx.strokeStyle = "#f59e0b";
    ctx.lineWidth = 1.5;
    ctx.moveTo(padLeft, thresholdY);
    ctx.lineTo(padLeft + chartW, thresholdY);
    ctx.stroke();
    ctx.setLineDash([]);

    // Draw Normal Baseline Threshold Area (< 10%)
    const baselineY = padTop + chartH - (10 / 100) * chartH;
    ctx.fillStyle = "rgba(16, 185, 129, 0.06)";
    ctx.fillRect(padLeft, baselineY, chartW, (10 / 100) * chartH);

    // Draw DDoS Probability Area Fill
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const prob = Math.min(100, Math.max(0, (r.ddos_probability || 0) * 100));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (prob / 100) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + (dataPoints.length - 1) * xStep, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
    grad.addColorStop(0, "rgba(56, 189, 248, 0.35)");
    grad.addColorStop(1, "rgba(56, 189, 248, 0.02)");
    ctx.fillStyle = grad;
    ctx.fill();

    // Draw DDoS Probability Curve Line
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const prob = Math.min(100, Math.max(0, (r.ddos_probability || 0) * 100));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (prob / 100) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#38bdf8";
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // Draw Data Point Dots
    dataPoints.forEach((r, idx) => {
        const prob = Math.min(100, Math.max(0, (r.ddos_probability || 0) * 100));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (prob / 100) * chartH;
        ctx.beginPath();
        ctx.arc(x, y, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = prob >= 62 ? "#f43f5e" : "#38bdf8";
        ctx.fill();
    });

    // Draw X-Axis Time Labels
    ctx.fillStyle = "#64748b";
    ctx.textAlign = "center";
    const labelStep = Math.max(1, Math.floor(dataPoints.length / 5));
    for (let i = 0; i < dataPoints.length; i += labelStep) {
        const ts = dataPoints[i].window_start || "";
        const label = ts.includes("T") ? ts.split("T")[1].split(".")[0] : ts.slice(-8);
        const x = padLeft + i * xStep;
        ctx.fillText(label, x, padTop + chartH + 16);
    }
}

/**
 * Supporting Non-Time-Series: Protocol Mix Doughnut
 */
function renderProtocolDonut(canvas, protocolsData) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const mix = (protocolsData && protocolsData.mix) ? protocolsData.mix : { "UDP": 212, "TCP": 20, "ICMP": 9 };

    // Canonical categories matching the UI legend
    const udpCount = Number(mix["UDP"] || 0);
    const tcpCount = Number(mix["TCP"] || 0);
    const icmpCount = Number(mix["ICMP"] || 0) + Number(mix["ICMPV6"] || 0);
    const mqttCount = Number(mix["MQTT"] || 0);

    let otherCount = 0;
    for (const [k, v] of Object.entries(mix)) {
        const uk = k.toUpperCase();
        if (uk !== "UDP" && uk !== "TCP" && uk !== "ICMP" && uk !== "ICMPV6" && uk !== "MQTT") {
            otherCount += Number(v || 0);
        }
    }

    const categories = [
        { key: "UDP", label: "UDP", count: udpCount, elId: "protoCountUDP", color: "#38bdf8" },
        { key: "TCP", label: "TCP", count: tcpCount, elId: "protoCountTCP", color: "#818cf8" },
        { key: "ICMP", label: "ICMP", count: icmpCount, elId: "protoCountICMP", color: "#f43f5e" },
        { key: "MQTT", label: "MQTT", count: mqttCount, elId: "protoCountMQTT", color: "#10b981" }
    ];
    if (otherCount > 0) {
        categories.push({ key: "OTHER", label: "OTHER", count: otherCount, elId: null, color: "#f59e0b" });
    }

    const totalCount = categories.reduce((sum, c) => sum + c.count, 0);

    // Compute normalized integer percentages that sum to 100% using Largest Remainder Method (Hamilton-Hare)
    let normPcts = categories.map(() => 0);
    if (totalCount > 0) {
        const rawPcts = categories.map(c => (c.count / totalCount) * 100);
        const floorPcts = rawPcts.map(p => Math.floor(p));
        let remainder = 100 - floorPcts.reduce((a, b) => a + b, 0);

        const indexedRemainders = rawPcts.map((p, i) => ({ index: i, frac: p - floorPcts[i], count: categories[i].count }))
            .filter(item => item.count > 0)
            .sort((a, b) => b.frac - a.frac);

        normPcts = [...floorPcts];
        for (let i = 0; i < remainder && i < indexedRemainders.length; i++) {
            normPcts[indexedRemainders[i].index]++;
        }
    }

    // Update Pills and legend with identical normalized values
    categories.forEach((cat, idx) => {
        cat.pct = normPcts[idx];
        if (cat.elId) {
            const el = document.getElementById(cat.elId);
            if (el) {
                el.textContent = `${cat.pct}% (${cat.count})`;
            }
        }
    });

    // Determine actual dominant protocol
    let dominant = categories[0];
    for (const c of categories) {
        if (c.count > dominant.count) {
            dominant = c;
        }
    }
    const centerVal = document.getElementById("donutPrimaryProto");
    const centerPct = document.getElementById("donutPrimaryPct");
    if (centerVal) centerVal.textContent = totalCount > 0 ? dominant.label : "IDLE";
    if (centerPct) centerPct.textContent = totalCount > 0 ? `${dominant.pct}%` : "0%";

    // Draw Crisp Doughnut Slices using identical normalized slices
    const centerX = width / 2;
    const centerY = height / 2;
    const outerRadius = Math.min(centerX, centerY) - 8;
    const innerRadius = outerRadius * 0.72;

    if (totalCount > 0) {
        let startAngle = -Math.PI / 2;
        categories.forEach((cat) => {
            if (cat.count <= 0) return;
            const sliceAngle = (cat.count / totalCount) * (Math.PI * 2);
            const endAngle = startAngle + sliceAngle;

            ctx.beginPath();
            ctx.arc(centerX, centerY, outerRadius, startAngle, endAngle);
            ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
            ctx.closePath();
            ctx.fillStyle = cat.color;
            ctx.fill();

            ctx.lineWidth = 2;
            ctx.strokeStyle = "#0d1627";
            ctx.stroke();

            startAngle = endAngle;
        });
    } else {
        ctx.beginPath();
        ctx.arc(centerX, centerY, outerRadius, 0, Math.PI * 2);
        ctx.arc(centerX, centerY, innerRadius, Math.PI * 2, 0, true);
        ctx.closePath();
        ctx.fillStyle = "rgba(70, 100, 140, 0.2)";
        ctx.fill();
    }
}


/* ==========================================================================
   4. PLANT MIMIC TOPOLOGY VISUALIZER
   ========================================================================== */
function updateTopology(topologyContext) {
    if (!topologyContext) return;

    const deviceCountEl = document.getElementById("topologyDeviceCount");
    const linkCountEl = document.getElementById("topologyLinkCount");
    const statusEl = document.getElementById("topologyStatus");
    const envEl = document.getElementById("topologyEnvironment");

    if (deviceCountEl) deviceCountEl.textContent = (topologyContext.nodes || []).length || 5;
    if (linkCountEl) linkCountEl.textContent = (topologyContext.links || []).length || 4;
    if (statusEl) statusEl.textContent = topologyContext.status || "ONLINE";
    if (envEl) envEl.textContent = (topologyContext.environment || "CONTROLLED SIMULATION").replace(/_/g, " ");
}

function updatePlantMimicVisuals(isAttack, attackVector) {
    const linkAttack = document.getElementById("linkAttack");
    const linkAttackBack = document.getElementById("linkAttackBack");
    const atkCircle = document.getElementById("atkCircle");
    const atkStatusText = document.getElementById("atkStatusText");
    const gatewayRing = document.getElementById("gatewayPulseRing");

    if (isAttack) {
        if (linkAttack) linkAttack.style.display = "block";
        if (linkAttackBack) linkAttackBack.style.stroke = "rgba(244, 63, 94, 0.6)";
        if (atkCircle) {
            atkCircle.setAttribute("stroke", "var(--red)");
            atkCircle.setAttribute("fill", "rgba(244, 63, 94, 0.25)");
        }
        if (atkStatusText) {
            atkStatusText.textContent = `ATTACK: ${String(attackVector || "FLOOD").toUpperCase()}`;
            atkStatusText.setAttribute("fill", "var(--red)");
        }
        if (gatewayRing) {
            gatewayRing.setAttribute("stroke", "var(--red)");
        }
    } else {
        if (linkAttack) linkAttack.style.display = "none";
        if (linkAttackBack) linkAttackBack.style.stroke = "rgba(244, 63, 94, 0.15)";
        if (atkCircle) {
            atkCircle.setAttribute("stroke", "#64748b");
            atkCircle.setAttribute("fill", "#200d14");
        }
        if (atkStatusText) {
            atkStatusText.textContent = "IDLE (LAB)";
            atkStatusText.setAttribute("fill", "#64748b");
        }
        if (gatewayRing) {
            gatewayRing.setAttribute("stroke", "#6366f1");
        }
    }
}


/* ==========================================================================
   5. ENERGY VS BASELINE (CANONICAL BACKEND CONTRACT)
   ========================================================================== */
function updateEnergy(energyData) {
    if (!energyData) return;
    const latest = Array.isArray(energyData.rows) && energyData.rows.length 
        ? energyData.rows[energyData.rows.length - 1] 
        : energyData;

    // Synchronized canonical fields: baseline_energy, tx_activity, rx_activity, cpu_activity
    const rate = Number(latest.energy_rate ?? 55.0);
    const base = Number(latest.baseline_energy ?? 55.0);
    const dev = Number(latest.energy_deviation ?? 0.0);
    const cause = latest.energy_cause || "MODELLED: baseline sensor activity (idle power state)";
    const tx = Number(latest.tx_activity ?? 4.0);
    const rx = Number(latest.rx_activity ?? 5.0);
    const cpu = Number(latest.cpu_activity ?? 6.0);

    const rateEl = document.getElementById("energyRate");
    const baseEl = document.getElementById("energyBaseline");
    const devEl = document.getElementById("energyDeviation");
    const devStat = document.getElementById("energyDevStat");
    const causeEl = document.getElementById("energyCause");

    if (rateEl) rateEl.textContent = rate.toFixed(1);
    if (baseEl) baseEl.textContent = base.toFixed(1);
    if (devEl) devEl.textContent = `${dev >= 0 ? "+" : ""}${(dev * 100).toFixed(1)}%`;
    if (devStat) {
        devStat.className = `energy-stat deviation ${dev > 0.5 ? "alert" : ""}`;
    }
    if (causeEl) causeEl.textContent = cause;

    // Contribution Progress Bars
    const txVal = document.getElementById("energyTxVal");
    const rxVal = document.getElementById("energyRxVal");
    const cpuVal = document.getElementById("energyCpuVal");
    const barTx = document.getElementById("barEnergyTx");
    const barRx = document.getElementById("barEnergyRx");
    const barCpu = document.getElementById("barEnergyCpu");

    if (txVal) txVal.textContent = `${tx.toFixed(1)}%`;
    if (rxVal) rxVal.textContent = `${rx.toFixed(1)}%`;
    if (cpuVal) cpuVal.textContent = `${cpu.toFixed(1)}%`;
    if (barTx) barTx.style.width = `${Math.min(100, Math.max(4, tx))}%`;
    if (barRx) barRx.style.width = `${Math.min(100, Math.max(5, rx))}%`;
    if (barCpu) barCpu.style.width = `${Math.min(100, Math.max(5, cpu))}%`;

    // Gateway Load KPI Card Sync
    const gwCpu = document.getElementById("gatewayCpuVal");
    const gwRam = document.getElementById("gatewayRamVal");
    const gwRadio = document.getElementById("gatewayRadioVal");
    if (gwCpu) gwCpu.textContent = cpu.toFixed(1);
    if (gwRam) gwRam.textContent = Number(latest.memory_activity ?? 22.0).toFixed(0);
    if (gwRadio) gwRadio.textContent = rx.toFixed(0);
}


/* ==========================================================================
   6. DETECTION & XAI EXPLAINABILITY
   ========================================================================== */
function updateDetection(latest) {
    if (!latest) return;

    const patternEl = document.getElementById("detPatternVal");
    const protocolEl = document.getElementById("detProtocolVal");
    const sourceEl = document.getElementById("detSourceVal");
    const intensityEl = document.getElementById("detIntensityVal");
    const anomalyEl = document.getElementById("detAnomalyScore");

    const scenario = latest.scenario_id || "normal";
    const isAttack = latest.prediction === "ATTACK" || latest.label === "ATTACK";
    const proto = latest.protocol || "UDP";
    const srcIp = latest.src_ip || (isAttack ? "10.42.0.250" : "10.42.0.11");
    const dstIp = latest.dst_ip || "10.42.0.1";
    const pps = Number(latest.packets_per_second || latest.packet_rate || 18.0);
    const prob = Number(latest.ddos_probability || (isAttack ? 0.99 : 0.05));

    if (patternEl) patternEl.textContent = scenario.toUpperCase();
    if (protocolEl) protocolEl.textContent = `${proto} (${proto === "UDP" ? "Port 5683 CoAP" : "Port 1883 MQTT"})`;
    if (sourceEl) sourceEl.textContent = `${srcIp} → ${dstIp}`;
    if (intensityEl) intensityEl.textContent = isAttack ? `SURGE (${pps.toFixed(0)} pkts/s)` : `BASELINE (${pps.toFixed(0)} pkts/s)`;
    if (anomalyEl) {
        anomalyEl.textContent = `${prob.toFixed(2)} (${isAttack ? "ANOMALOUS" : "BENIGN"})`;
        anomalyEl.className = `detail-val ${isAttack ? "threat" : "safe"}`;
    }

    updatePlantMimicVisuals(isAttack, scenario);
}

function updateExplainability(exp) {
    if (!exp) return;
    const container = document.getElementById("evidenceItemsContainer");
    if (!container) return;

    const evidence = exp.observed_evidence || [];
    if (!evidence.length) {
        container.innerHTML = `
            <div class="evidence-item">Packet rate conforms to baseline (20.0 pps nominal).</div>
            <div class="evidence-item">Source identity matches authenticated sensor registry.</div>
            <div class="evidence-item">No protocol ratio or byte spike detected.</div>
        `;
        return;
    }

    container.innerHTML = evidence.map(item => `
        <div class="evidence-item">${escapeHtml(item)}</div>
    `).join("");
}


/* ==========================================================================
   7. DYNAMIC ZERO-TRUST IAM TABLE
   ========================================================================== */
function updateIAM(iamData) {
    const listBody = document.getElementById("iamDeviceList");
    const atkTrustVal = document.getElementById("atkTrustScoreVal");
    if (!iamData || !iamData.identities) return;

    const identities = iamData.identities;
    const atk = identities.find(i => i.identity === "ATK-01");
    if (atk && atkTrustVal) {
        atkTrustVal.textContent = atk.trust_score.toFixed(1);
    }

    if (!listBody) return;
    listBody.innerHTML = identities.map(dev => {
        const isAuth = Boolean(dev.authenticated);
        const isAllow = isAuth && dev.role !== "untrusted" && dev.trust_score >= 40.0;
        const trustColor = dev.trust_score >= 70 ? "var(--green)" : (dev.trust_score >= 40 ? "var(--amber)" : "var(--red)");
        const mfa = dev.mfa_status || (dev.role === "operator" ? "VERIFIED" : (dev.role === "untrusted" ? "FAILED" : "NOT_REQUIRED"));
        const mfaBadgeClass = (mfa === "VERIFIED" || mfa === "NOT_REQUIRED") ? "iam-allow" : "iam-deny";
        
        return `
            <tr>
                <td><strong>${escapeHtml(dev.identity)}</strong></td>
                <td style="text-transform: capitalize;">${escapeHtml(dev.role)}</td>
                <td><span class="iam-badge ${isAuth ? 'iam-allow' : 'iam-deny'}">${isAuth ? 'VERIFIED' : 'UNVERIFIED'}</span></td>
                <td><span class="iam-badge ${mfaBadgeClass}">${escapeHtml(mfa.replace('_', ' '))}</span></td>
                <td><span class="iam-badge ${isAllow ? 'iam-allow' : 'iam-deny'}">${isAllow ? 'ALLOW' : 'DENY'}</span></td>
                <td><strong style="color: ${trustColor}; font-family: var(--font-mono);">${dev.trust_score.toFixed(1)}</strong></td>
            </tr>
        `;
    }).join("");
}


/* ==========================================================================
   8. INCIDENT LIFECYCLE (HORIZONTAL 7-STEP STEPPER)
   ========================================================================== */
const LIFECYCLE_STEP_MAP = {
    "DETECTED": 0,
    "ANALYZING": 1,
    "TRIAGED": 1,
    "RESPONDING": 2,
    "CONTAINED": 3,
    "RECOVERING": 4,
    "RESOLVED": 5,
    "CLOSED": 6
};

function isBaselineState(state) {
    if (!state) return true;
    const s = String(state).toUpperCase();
    return ["NORMAL", "IDLE", "OBSERVED", "BASELINE", "NONE"].includes(s);
}

// Global reference to track active or transitioning incident in HMI session
let hmiTargetIncident = null;

function updateLifecycle(targetIncident, summary, telemetryContext) {
    let state = "NORMAL";
    let isNormal = true;
    let inc = targetIncident || (summary && summary.active_incident ? summary.active_incident : null);

    if (inc && inc.lifecycle_state && !isBaselineState(inc.lifecycle_state)) {
        state = inc.lifecycle_state.toUpperCase();
        isNormal = false;
    } else if (summary && summary.lifecycle_state && !isBaselineState(summary.lifecycle_state)) {
        state = summary.lifecycle_state.toUpperCase();
        isNormal = false;
    }

    const stateBadge = document.getElementById("lifecycleState");
    const stageText = document.getElementById("lifecycleStage");
    const recoveryText = document.getElementById("lifecycleRecovery");
    const normalBadge = document.getElementById("lifecycleNormalBadge");
    const activeIdEl = document.getElementById("activeIncId");

    if (isNormal) {
        if (stateBadge) {
            stateBadge.textContent = "NORMAL";
            stateBadge.style.color = "var(--green)";
        }
        if (stageText) {
            stageText.textContent = "BASELINE OBSERVATION";
        }
        if (recoveryText) {
            recoveryText.textContent = (summary && summary.recovery_state) || "MONITORING";
            recoveryText.style.color = "var(--green)";
        }
        if (normalBadge) {
            normalBadge.classList.add("active");
        }
        if (activeIdEl && (!inc || ["RESOLVED", "CLOSED"].includes(inc.lifecycle_state))) {
            activeIdEl.innerHTML = `<span style="color: var(--green);">NONE (BASELINE / SYSTEM CLEAR)</span>`;
        }
    } else {
        if (stateBadge) {
            stateBadge.textContent = state;
            if (["DETECTED", "ANALYZING", "TRIAGED", "RESPONDING", "CONTAINED"].includes(state)) {
                stateBadge.style.color = "var(--red)";
            } else if (state === "RECOVERING") {
                stateBadge.style.color = "var(--amber)";
            } else {
                stateBadge.style.color = "var(--green)";
            }
        }
        if (stageText) {
            const stageDesc = {
                "DETECTED": "THREAT DETECTED • TRIAGING",
                "ANALYZING": "EVIDENCE CORRELATION",
                "TRIAGED": "EVIDENCE CORRELATION",
                "RESPONDING": "AUTONOMOUS RESPONSE ENGAGED",
                "CONTAINED": "SIMULATED MITIGATION ACTIVE (DRY_RUN)",
                "RECOVERING": "OBSERVING RECOVERY STREAK",
                "RESOLVED": "TELEMETRY RECOVERED • VERIFIED",
                "CLOSED": "INCIDENT CLOSED • AUDIT FINALIZED"
            }[state] || (telemetryContext && telemetryContext.lifecycle_stage ? telemetryContext.lifecycle_stage.replace(/_/g, " ") : "AUTONOMOUS RESPONSE");
            stageText.textContent = stageDesc;
        }
        if (recoveryText) {
            if (inc && inc.recovery_state) {
                recoveryText.textContent = inc.recovery_state;
                recoveryText.style.color = inc.recovery_state === "VERIFIED" ? "var(--green)" : "var(--amber)";
            } else {
                const recVal = (state === "RESOLVED" || state === "CLOSED") ? "VERIFIED" : (state === "RECOVERING" ? "PENDING" : "CONTAINED_IN_SOFTWARE");
                recoveryText.textContent = recVal;
                recoveryText.style.color = (state === "RESOLVED" || state === "CLOSED") ? "var(--green)" : "var(--amber)";
            }
        }
        if (normalBadge) {
            normalBadge.classList.remove("active");
        }
        if (activeIdEl && inc && inc.incident_id) {
            if (["RESOLVED", "CLOSED"].includes(state)) {
                activeIdEl.innerHTML = `<strong style="color: var(--green);">${escapeHtml(inc.incident_id)} (${escapeHtml(state)})</strong>`;
            } else {
                activeIdEl.innerHTML = `<strong style="color: var(--red);">${escapeHtml(inc.incident_id)} (${escapeHtml(state)})</strong>`;
            }
        }
    }

    // Horizontal 7-Step Progression
    const stepOrder = ["DETECTED", "ANALYZING", "RESPONDING", "CONTAINED", "RECOVERING", "RESOLVED", "CLOSED"];
    const currentIdx = LIFECYCLE_STEP_MAP.hasOwnProperty(state) ? LIFECYCLE_STEP_MAP[state] : -1;

    stepOrder.forEach((step, idx) => {
        const id = `stepNode${step.charAt(0) + step.slice(1).toLowerCase()}`;
        const node = document.getElementById(id);
        if (!node) return;

        node.className = "step-node";
        if (isNormal || currentIdx < 0) {
            // In baseline normal, stepper rests in ready/idle state
            return;
        }

        if (idx === currentIdx) {
            if (["DETECTED", "ANALYZING", "RESPONDING", "CONTAINED"].includes(step)) {
                node.classList.add("threat-active");
            } else {
                node.classList.add("resolved-active");
            }
        } else if (idx < currentIdx) {
            node.classList.add("resolved-active");
        }
    });

    // Update Autonomous Mitigation Pipeline Flow Steps
    const pipeCard = document.querySelector(".auto-pipeline-card");
    if (pipeCard) {
        const flowSteps = pipeCard.querySelectorAll(".flow-step");
        if (flowSteps && flowSteps.length >= 7) {
            const pipeIdx = {
                "DETECTED": 1,
                "ANALYZING": 2,
                "TRIAGED": 2,
                "RESPONDING": 3,
                "CONTAINED": 4,
                "RECOVERING": 5,
                "RESOLVED": 6,
                "CLOSED": 7
            }[state] || (isNormal ? 0 : 1);

            flowSteps.forEach((s, idx) => {
                s.classList.remove("auto-done", "active", "manual-req", "pending");
                if (idx === 6) { // Step 7: Operator Audit Closure
                    if (pipeIdx >= 7) {
                        s.classList.add("auto-done");
                        s.textContent = "✓ Operator Audit Closed";
                    } else if (pipeIdx === 6) {
                        s.classList.add("manual-req", "active");
                        s.textContent = "● Operator Closure Required";
                    } else {
                        s.classList.add("manual-req");
                        s.textContent = "○ Operator Audit Closure";
                    }
                } else {
                    if (pipeIdx > idx) {
                        s.classList.add("auto-done");
                    } else if (pipeIdx === idx + 1) {
                        s.classList.add("active");
                    } else {
                        s.classList.add("pending");
                    }
                }
            });
        }
    }
}


/* ==========================================================================
   9. INCIDENT JOURNAL & THREAT EVENTS
   ========================================================================== */
function updateIncidents(incidents) {
    const table = document.getElementById("incidentsTable");
    const countEl = document.getElementById("incidentCount");
    const activeIdEl = document.getElementById("activeIncId");
    const actionControls = document.getElementById("incidentActionControls");
    const activeCountEl = document.getElementById("activeIncidentCount");
    const histCountEl = document.getElementById("historicalIncidentCount");

    const activeIncs = (incidents || []).filter(i => !["RESOLVED", "CLOSED"].includes(i.lifecycle_state));
    const histIncs = (incidents || []).filter(i => ["RESOLVED", "CLOSED"].includes(i.lifecycle_state));

    if (countEl) countEl.textContent = incidents ? incidents.length : 0;
    if (activeCountEl) activeCountEl.textContent = activeIncs.length;
    if (histCountEl) histCountEl.textContent = histIncs.length;

    if (!incidents || !incidents.length) {
        if (table) {
            table.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 18px;">No active or historical incidents recorded in historian.</td></tr>`;
        }
        if (activeIdEl) activeIdEl.innerHTML = `<span style="color: var(--green);">NONE (BASELINE / OPERATIONAL)</span>`;
        if (actionControls) actionControls.innerHTML = "";
        return;
    }

    // Explicitly distinguish current active incident from historical audit log
    const activeInc = incidents.find(i => !["RESOLVED", "CLOSED"].includes(i.lifecycle_state));
    const latest = incidents[0];

    if (activeIdEl) {
        if (activeInc) {
            activeIdEl.innerHTML = `<strong style="color: var(--red);">${escapeHtml(activeInc.incident_id)} (${escapeHtml(activeInc.lifecycle_state)})</strong>`;
        } else {
            activeIdEl.innerHTML = `<span style="color: var(--green);">NONE (BASELINE / SYSTEM CLEAR)</span>`;
        }
    }

    // Operator Action Quick Controls for active incident or latest resolved
    if (actionControls) {
        const targetInc = activeInc || (hmiTargetIncident && ["RESOLVED", "CLOSED"].includes(hmiTargetIncident.lifecycle_state) ? hmiTargetIncident : (latest && latest.lifecycle_state === "RESOLVED" ? latest : null));
        const st = targetInc ? targetInc.lifecycle_state : "";
        if (["CONTAINED", "RECOVERING", "RESPONDING", "DETECTED"].includes(st)) {
            actionControls.innerHTML = `<button class="btn-sim-action btn-recover" type="button" onclick="transitionIncidentState('${targetInc.incident_id}', 'RESOLVED')">Resolve ${targetInc.incident_id}</button>`;
        } else if (st === "RESOLVED") {
            actionControls.innerHTML = `<button class="btn-sim-action" type="button" onclick="transitionIncidentState('${targetInc.incident_id}', 'CLOSED')">Close ${targetInc.incident_id}</button>`;
        } else if (st === "CLOSED" && hmiTargetIncident && hmiTargetIncident.incident_id === targetInc.incident_id) {
            actionControls.innerHTML = `<button class="btn-sim-action btn-recover" type="button" onclick="resetLifecycleToBaseline()">Reset Stepper to Baseline</button>`;
        } else {
            actionControls.innerHTML = "";
        }
    }

    if (!table) return;
    table.innerHTML = incidents.map(inc => {
        const state = inc.lifecycle_state || "UNKNOWN";
        const isActive = !["RESOLVED", "CLOSED"].includes(state);
        const sev = inc.severity || "MEDIUM";
        const sevClass = (sev === "CRITICAL" || sev === "HIGH") ? "color: var(--red);" : "color: var(--green);";
        const dt = (inc.updated_at || inc.created_at || "").replace("T", " ").split(".")[0];

        let actionBtn = "—";
        if (["CONTAINED", "RECOVERING", "RESPONDING", "DETECTED"].includes(state)) {
            actionBtn = `<button class="btn-sim-action btn-recover" type="button" onclick="transitionIncidentState('${inc.incident_id}', 'RESOLVED')">Resolve</button>`;
        } else if (state === "RESOLVED") {
            actionBtn = `<button class="btn-sim-action" type="button" onclick="transitionIncidentState('${inc.incident_id}', 'CLOSED')">Close</button>`;
        }

        let stateBadge;
        if (isActive) {
            stateBadge = `<span class="iam-badge iam-deny">ACTIVE: ${escapeHtml(state)}</span>`;
        } else if (state === "RESOLVED") {
            stateBadge = `<span class="iam-badge iam-allow">RESOLVED</span>`;
        } else {
            stateBadge = `<span class="iam-badge" style="background: rgba(100, 116, 139, 0.2); color: var(--text-muted); border: 1px solid rgba(100, 116, 139, 0.3);">CLOSED</span>`;
        }

        return `
            <tr class="${isActive ? 'active-incident-row' : ''}">
                <td style="font-family: monospace; color: var(--cyan);">${escapeHtml(inc.incident_id)}</td>
                <td style="font-size: 10px; color: var(--text-muted);">${dt}</td>
                <td><strong>${escapeHtml(inc.device_id || "10.42.0.250")}</strong></td>
                <td>${escapeHtml(inc.attack_type || "udp_flood")}</td>
                <td><strong style="${sevClass}">${sev}</strong></td>
                <td style="font-family: monospace;">${inc.confidence ? (inc.confidence * 100).toFixed(0) + "%" : "—"}</td>
                <td>
                    <div style="display: flex; align-items: center; gap: 4px;">
                        ${stateBadge}
                        <span class="safety-tag" style="font-size: 8px;">SIM</span>
                    </div>
                </td>
                <td style="color: ${inc.recovery_state === 'VERIFIED' ? 'var(--green)' : 'var(--amber)'}; font-size: 10px;">${inc.recovery_state || "PENDING"}</td>
                <td style="color: var(--cyan);">${escapeHtml(inc.response_action || "ISOLATE")}</td>
                <td>${actionBtn}</td>
            </tr>
        `;
    }).join("");
}

function updateEvents(events) {
    const table = document.getElementById("eventsTable");
    const countEl = document.getElementById("eventCount");
    if (!table) return;
    if (countEl) countEl.textContent = events ? events.length : 0;
    if (!events || !events.length) {
        table.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 12px;">No threat events recorded yet.</td></tr>`;
        return;
    }

    table.innerHTML = events.slice(0, 10).map(ev => {
        const dt = (ev.timestamp || "").replace("T", " ").split(".")[0];
        return `
            <tr>
                <td style="font-family: monospace; font-size: 10px; color: var(--text-muted);">${dt}</td>
                <td style="font-family: monospace;">${escapeHtml(ev.src_ip || "10.42.0.250")}</td>
                <td style="font-family: monospace;">${escapeHtml(ev.dst_ip || "10.42.0.1")}</td>
                <td style="font-family: monospace; color: var(--red);">${(ev.packet_rate || ev.packets_per_second || 0).toFixed(1)}</td>
                <td><span class="iam-badge iam-deny">${escapeHtml(ev.prediction || "ATTACK")}</span></td>
                <td style="font-family: monospace;">${((ev.ddos_probability || 0.99) * 100).toFixed(0)}%</td>
                <td style="color: var(--cyan);">${escapeHtml(ev.security_action || "ISOLATE")}</td>
                <td><strong style="color: var(--red);">${escapeHtml(ev.severity || "HIGH")}</strong></td>
            </tr>
        `;
    }).join("");
}


/* ==========================================================================
   10. MODEL ASSURANCE & 2x2 CONFUSION MATRIX
   ========================================================================== */
function updateModelAssurance(maData) {
    if (!maData) return;
    const setT = (id, text) => {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    };

    const metrics = maData.metrics || {};
    if (metrics.f1 !== null && metrics.f1 !== undefined) {
        setT("metricF1", `${(metrics.f1 * 100).toFixed(1)}%`);
    }
    if (metrics.precision !== null && metrics.precision !== undefined) {
        setT("metricPrecision", `${(metrics.precision * 100).toFixed(1)}%`);
    }
    if (metrics.recall !== null && metrics.recall !== undefined) {
        setT("metricRecall", `${(metrics.recall * 100).toFixed(1)}%`);
    }
    if (metrics.false_positive_rate !== null && metrics.false_positive_rate !== undefined) {
        setT("metricFPR", `${(metrics.false_positive_rate * 100).toFixed(1)}%`);
    }
    if (metrics.roc_auc !== null && metrics.roc_auc !== undefined) {
        setT("metricAUC", metrics.roc_auc.toFixed(3));
    }
    if (metrics.brier_score_calibrated !== null && metrics.brier_score_calibrated !== undefined) {
        setT("metricBrier", metrics.brier_score_calibrated.toFixed(5));
    }
    if (metrics.scenario_held_out_f1 !== null && metrics.scenario_held_out_f1 !== undefined) {
        setT("metricHeldOut", `${(metrics.scenario_held_out_f1 * 100).toFixed(1)}% F1`);
    }
    if (maData.model_architecture) {
        setT("metricModelName", maData.model_architecture);
    }

    // Update 2x2 Confusion Matrix
    const cm = maData.confusion_matrix || {};
    if (cm.true_negative !== null && cm.true_negative !== undefined) {
        setT("cmTN", cm.true_negative);
    }
    if (cm.false_positive !== null && cm.false_positive !== undefined) {
        setT("cmFP", cm.false_positive);
    }
    if (cm.false_negative !== null && cm.false_negative !== undefined) {
        setT("cmFN", cm.false_negative);
    }
    if (cm.true_positive !== null && cm.true_positive !== undefined) {
        setT("cmTP", cm.true_positive);
    }
}


/* ==========================================================================
   11. RAW SAMPLE FLOWS TABLE (DYNAMIC FROM TELEMETRY)
   ========================================================================== */
function updateSampleFlows(rows) {
    const tbody = document.getElementById("sampleFlowsTableBody");
    if (!tbody) return;

    if (!rows || !rows.length) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 14px;">No sample telemetry flows recorded.</td></tr>`;
        return;
    }

    // Display most recent 12 flows
    const sample = rows.slice(-12).reverse();
    tbody.innerHTML = sample.map(r => {
        const dt = (r.window_start || "").replace("T", " ").split(".")[0];
        const isAtk = r.prediction === "ATTACK";
        const proto = r.protocol || "UDP";
        const port = proto === "UDP" ? 5683 : (proto === "TCP" ? 1883 : 0);
        const prob = ((r.ddos_probability || 0) * 100).toFixed(0);

        return `
            <tr>
                <td style="font-family: monospace; font-size: 10px; color: var(--text-muted);">${dt}</td>
                <td style="font-family: monospace;">${escapeHtml(r.src_ip || "10.42.0.11")}</td>
                <td style="font-family: monospace;">${escapeHtml(r.dst_ip || "10.42.0.1")}</td>
                <td>${escapeHtml(proto)}</td>
                <td style="font-family: monospace; color: ${isAtk ? 'var(--red)' : 'var(--green)'};">${(r.packets_per_second || 0).toFixed(1)}</td>
                <td style="font-family: monospace;">${(r.average_packet_size || 64).toFixed(0)} B</td>
                <td><span class="iam-badge ${isAtk ? 'iam-deny' : 'iam-allow'}">${isAtk ? 'ATTACK' : 'NORMAL'}</span></td>
                <td style="font-family: monospace;">${prob}%</td>
                <td style="color: ${isAtk ? 'var(--red)' : 'var(--green)'};">${escapeHtml(r.security_action || 'PASS')}</td>
                <td style="font-size: 9.5px; color: var(--text-muted);">${escapeHtml(r.provenance || 'SIMULATED')}</td>
            </tr>
        `;
    }).join("");
}


/* ==========================================================================
   12. CONTROLLED ATTACK CONSOLE (100% IN-PROCESS SIMULATION)
   ========================================================================== */
async function runControlledDemo() {
    const button = document.getElementById("run-demo-btn");
    const banner = document.getElementById("simStatusBanner");
    const detail = document.getElementById("simStatusDetail");

    if (button) {
        button.disabled = true;
        button.textContent = "LAUNCHING CONTROLLED DEMO...";
    }
    if (banner) {
        banner.textContent = "STARTING DEMO...";
        banner.style.color = "var(--amber)";
    }

    try {
        // Stop any active simulations
        try {
            await fetch("/api/simulations/stop", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({})
            });
        } catch (_) {}

        // Launch in-process UDP Flood profile (Canonical endpoint: POST /api/simulations/start)
        const response = await fetch("/api/simulations/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                scenario_id: "udp_flood",
                intensity: 3,
                duration: 10
            })
        });

        if (response.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (response.status === 403) {
            const errData = await response.json().catch(() => ({}));
            if (banner) {
                banner.textContent = "DEMO FORBIDDEN";
                banner.style.color = "var(--red)";
            }
            if (detail) detail.textContent = errData.error || "Forbidden: Insufficient privileges";
            alert(errData.error || "Forbidden: ADMIN role required to run simulations");
            return;
        }
        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${response.status}`);
        }

        if (banner) {
            banner.textContent = "SIMULATING ATTACK (UDP FLOOD)";
            banner.style.color = "var(--red)";
        }
        if (detail) {
            detail.textContent = "Active profile: udp_flood (Intensity: 3, Duration: 10s) • In-process generator only";
        }

        await new Promise(r => setTimeout(r, 400));
        await refreshDashboard();

    } catch (error) {
        console.error("Controlled demo failed:", error);
        if (banner) {
            banner.textContent = "DEMO ERROR";
            banner.style.color = "var(--red)";
        }
        if (detail) detail.textContent = error.message;
    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "⚡ RUN CONTROLLED DEMO";
        }
    }
}

window.runControlledDemo = runControlledDemo;

window.triggerScenario = async function(scenarioId, intensity = 3, duration = 10) {
    const banner = document.getElementById("simStatusBanner");
    const detail = document.getElementById("simStatusDetail");
    if (banner) {
        banner.textContent = `STARTING ${scenarioId.toUpperCase()}...`;
        banner.style.color = "var(--amber)";
    }

    try {
        const res = await fetch("/api/simulations/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario_id: scenarioId, intensity, duration })
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const data = await res.json().catch(() => ({}));
            if (banner) {
                banner.textContent = "SIMULATION FORBIDDEN";
                banner.style.color = "var(--red)";
            }
            if (detail) detail.textContent = data.error || "Forbidden: Insufficient privileges";
            alert(data.error || "Forbidden: ADMIN role required to trigger simulations");
            return;
        }
        const data = await res.json();
        if (res.ok) {
            if (banner) {
                banner.textContent = scenarioId === "normal" ? "NORMAL RHYTHM ACTIVE" : `SIMULATING ${scenarioId.toUpperCase()}`;
                banner.style.color = scenarioId === "normal" ? "var(--green)" : "var(--red)";
            }
            if (detail) detail.textContent = `Profile: ${scenarioId} (Intensity: ${intensity}, Duration: ${duration}s)`;
            refreshDashboard();
        } else {
            if (banner) {
                banner.textContent = "SIMULATION FAILED";
                banner.style.color = "var(--red)";
            }
            if (detail) detail.textContent = data.error || "Request failed";
        }
    } catch (e) {
        console.error("Simulation trigger failed:", e);
    }
};

window.startSimulation = window.triggerScenario;

window.stopCurrentSimulation = async function() {
    const banner = document.getElementById("simStatusBanner");
    const detail = document.getElementById("simStatusDetail");
    try {
        const res = await fetch("/api/simulations/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const err = await res.json().catch(() => ({}));
            alert(err.error || "Forbidden: ADMIN role required to stop simulations");
            return;
        }
        if (banner) {
            banner.textContent = "SIMULATION STOPPED";
            banner.style.color = "var(--text-secondary)";
        }
        if (detail) detail.textContent = "Active profile halted. Baseline rhythm active.";
        refreshDashboard();
    } catch (e) {
        console.error("Stop simulation failed:", e);
    }
};

window.toggleResponseMode = async function() {
    const nextAuto = !window.currentAutoResponse;
    const mode = nextAuto ? "DRY_RUN" : "MANUAL";
    const textEl = document.getElementById("btnResponseModeText");
    const btnEl = document.getElementById("btnResponseMode");

    try {
        const res = await fetch("/api/settings/mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: mode, auto: nextAuto })
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const err = await res.json().catch(() => ({}));
            alert(err.error || "Forbidden: ADMIN role required to toggle response mode");
            return;
        }
        if (res.ok) {
            window.currentAutoResponse = nextAuto;
            if (textEl) textEl.textContent = window.currentAutoResponse ? "AUTO: ON" : "MANUAL: ACTIVE";
            if (btnEl) btnEl.className = `btn-mode-toggle ${window.currentAutoResponse ? 'active' : ''}`;
            const modeTag = document.getElementById("mitigationModeTag");
            if (modeTag) modeTag.textContent = mode;
            const respMode = document.getElementById("respPolicyMode");
            if (respMode) respMode.textContent = `${window.currentAutoResponse ? 'AUTO' : 'MANUAL'} (${mode})`;
        }
    } catch (e) {
        console.error("Mode toggle failed:", e);
    }
};

window.executeManualAction = async function(actionName) {
    try {
        const res = await fetch("/api/manual/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: actionName, actor: "operator" })
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const err = await res.json().catch(() => ({}));
            alert(err.error || "Forbidden: Insufficient permissions for manual action");
            return;
        }
        if (res.ok) {
            refreshDashboard();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(err.error || `Action failed with status ${res.status}`);
        }
    } catch (e) {
        console.error("Manual action failed:", e);
    }
};

window.resetLifecycleToBaseline = async function() {
    hmiTargetIncident = null;
    try {
        const res = await fetch("/api/simulations/reset", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
    } catch (e) {
        console.error("Backend reset failed:", e);
    } finally {
        refreshDashboard();
        if (typeof refreshAdminAlerts === "function") {
            refreshAdminAlerts();
        }
    }
};

window.transitionIncidentState = async function(incidentId, targetState) {
    try {
        const res = await fetch(`/api/incidents/${incidentId}/transition`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ state: targetState, actor: "operator", note: "Operator transitioned state via HMI" })
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const err = await res.json().catch(() => ({}));
            alert(err.error || `Forbidden: Cannot transition incident to ${targetState}`);
            return;
        }
        if (res.ok) {
            const updated = await res.json();
            hmiTargetIncident = updated;
            refreshDashboard();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(err.error || `Transition failed with status ${res.status}`);
        }
    } catch (e) {
        console.error("Transition failed:", e);
    }
};


/* ==========================================================================
   13. MASTER REFRESH & SSE INTEGRATION
   ========================================================================== */
async function refreshDashboard() {
    try {
        // 1. Status & Summary
        let statusObj = null;
        const statusRes = await fetch("/api/status", { cache: "no-store" });
        if (statusRes.ok) {
            statusObj = await statusRes.json();
            const sysStatus = document.getElementById("systemStatus");
            const dot = document.getElementById("statusDot");
            const isOnline = statusObj.status === "ONLINE";
            if (sysStatus) sysStatus.textContent = isOnline ? "ONLINE" : "NO DATA";
            if (dot) {
                dot.classList.toggle("online", isOnline);
                dot.classList.toggle("offline", !isOnline);
            }
            updateSummary(statusObj.summary || {}, statusObj);
        }

        // 2. Telemetry & Time-Series Charts
        let latestTel = null;
        const liveRes = await fetch("/api/telemetry", { cache: "no-store" });
        let liveRows = [];
        if (liveRes.ok) {
            const liveData = await liveRes.json();
            liveRows = liveData.rows || [];
            if (liveRows.length) {
                latestTel = liveRows[liveRows.length - 1];
                updateDetection(latestTel);
                updateExplainability(latestTel.explainability_context);
                updateSampleFlows(liveRows);
            }
            renderHistorianChart(document.getElementById("trafficChart"), liveRows);
            renderEnergyChart(document.getElementById("energyChart"), liveRows);
            const threatCanvas = document.getElementById("threatChart");
            if (threatCanvas) renderThreatChart(threatCanvas, liveRows);
        }

        // 3. Protocols Doughnut
        const protoRes = await fetch("/api/protocols", { cache: "no-store" });
        if (protoRes.ok) {
            const protoData = await protoRes.json();
            renderProtocolDonut(document.getElementById("protocolDonutChart"), protoData);
        }

        // 4. Energy Model
        const energyRes = await fetch("/api/energy", { cache: "no-store" });
        if (energyRes.ok) {
            const energyData = await energyRes.json();
            updateEnergy(energyData);
        }

        // 5. Topology Mimic
        const topoRes = await fetch("/api/topology", { cache: "no-store" });
        if (topoRes.ok) {
            const topoData = await topoRes.json();
            updateTopology(topoData);
        }

        // 6. IAM Dynamic Table
        const iamRes = await fetch("/api/iam", { cache: "no-store" });
        if (iamRes.ok) {
            const iamData = await iamRes.json();
            updateIAM(iamData);
        }

        // 7. Incidents Journal
        let incidentsList = [];
        const incRes = await fetch("/api/incidents", { cache: "no-store" });
        if (incRes.ok) {
            const incData = await incRes.json();
            incidentsList = incData.incidents || [];
            updateIncidents(incidentsList);
        }

        // Determine active or transitioning incident for the 7-step stepper
        const activeUnclosed = incidentsList.find(i => !["RESOLVED", "CLOSED"].includes(i.lifecycle_state));
        let stepperIncident = null;
        if (activeUnclosed) {
            stepperIncident = activeUnclosed;
            hmiTargetIncident = activeUnclosed;
        } else if (hmiTargetIncident) {
            const refreshedTarget = incidentsList.find(i => i.incident_id === hmiTargetIncident.incident_id);
            if (refreshedTarget) {
                hmiTargetIncident = refreshedTarget;
                stepperIncident = refreshedTarget;
            } else {
                stepperIncident = hmiTargetIncident;
            }
        } else if (incidentsList.length && incidentsList[0].lifecycle_state === "RESOLVED") {
            stepperIncident = incidentsList[0];
            hmiTargetIncident = incidentsList[0];
        }

        // Update the 7-Step Stepper using the canonical incident state
        updateLifecycle(stepperIncident, statusObj ? statusObj.summary : {}, latestTel ? latestTel.lifecycle_context : null);

        // 8. Recent Threat Events
        const evRes = await fetch("/api/events", { cache: "no-store" });
        if (evRes.ok) {
            const evData = await evRes.json();
            updateEvents(evData.events);
        }

        // 9. Model Assurance & Confusion Matrix
        const maRes = await fetch("/api/model-assurance", { cache: "no-store" });
        if (maRes.ok) {
            const maData = await maRes.json();
            updateModelAssurance(maData);
        }

        // 10. Administrative Security Layer
        await refreshAdminSection();

    } catch (error) {
        console.error("Dashboard refresh error:", error);
    }
}

function escapeHtml(str) {
    return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* ==========================================================================
   10. SIDEBAR NAVIGATION & COLLAPSIBLE CONTROLS
   ========================================================================== */
function toggleSidebar() {
    const sidebar = document.getElementById("hmiSidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    const toggleBtn = document.getElementById("sidebarToggle");
    if (!sidebar) return;

    if (window.innerWidth <= 1100) {
        const isOpen = sidebar.classList.toggle("mobile-open");
        if (backdrop) backdrop.classList.toggle("active", isOpen);
        if (toggleBtn) toggleBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
    } else {
        const isExpanded = sidebar.classList.toggle("expanded");
        if (backdrop) backdrop.classList.toggle("active", isExpanded);
        if (toggleBtn) toggleBtn.setAttribute("aria-expanded", isExpanded ? "true" : "false");
    }
}

function collapseSidebar() {
    const sidebar = document.getElementById("hmiSidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    const toggleBtn = document.getElementById("sidebarToggle");
    if (sidebar) {
        sidebar.classList.remove("expanded");
        sidebar.classList.remove("mobile-open");
    }
    if (backdrop) {
        backdrop.classList.remove("active");
    }
    if (toggleBtn) {
        toggleBtn.setAttribute("aria-expanded", "false");
    }
}

window.toggleSidebar = toggleSidebar;
window.collapseSidebar = collapseSidebar;

function initSidebarNavigation() {
    const sidebar = document.getElementById("hmiSidebar");
    if (!sidebar) return;

    const links = sidebar.querySelectorAll(".hmi-sidebar-link");
    links.forEach(link => {
        link.addEventListener("click", (e) => {
            const targetId = link.getAttribute("data-target") || (link.getAttribute("href") || "").replace("#", "");
            const targetEl = document.getElementById(targetId);
            if (targetEl) {
                e.preventDefault();
                targetEl.scrollIntoView({ behavior: "smooth", block: "start" });
                // Collapse expanded navigation drawer on desktop or mobile upon link selection
                collapseSidebar();
                links.forEach(l => l.classList.remove("active"));
                link.classList.add("active");
            }
        });
    });

    // Close expanded sidebar on Escape key
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            collapseSidebar();
        }
    });

    // Scroll-Spy to highlight current section
    const sectionIds = [
        "sec-kpis",
        "sec-status-gauges",
        "sec-telemetry",
        "sec-topology",
        "sec-energy",
        "sec-iam",
        "sec-protocol-stack",
        "sec-lifecycle",
        "sec-incidents",
        "sec-comparison",
        "sec-assurance",
        "sec-controls",
        "sec-admin-overview",
        "sec-admin-alerts",
        "sec-admin-users",
        "sec-admin-audit",
        "sec-admin-posture"
    ];

    let ticking = false;
    window.addEventListener("scroll", () => {
        if (!ticking) {
            window.requestAnimationFrame(() => {
                const scrollPos = window.scrollY + 160;
                let activeSecId = "";
                for (const id of sectionIds) {
                    const el = document.getElementById(id);
                    if (el) {
                        const top = el.offsetTop;
                        const height = el.offsetHeight;
                        if (scrollPos >= top && scrollPos < top + height) {
                            activeSecId = id;
                            break;
                        }
                    }
                }
                if (activeSecId) {
                    links.forEach(l => {
                        const t = l.getAttribute("data-target") || (l.getAttribute("href") || "").replace("#", "");
                        if (t === activeSecId) {
                            l.classList.add("active");
                        } else {
                            l.classList.remove("active");
                        }
                    });
                }
                ticking = false;
            });
            ticking = true;
        }
    }, { passive: true });
}

/* ==========================================================================
   SERVER-SENT EVENTS (SSE) & REFRESH COALESCING
   ========================================================================== */

let refreshTimer = null;
let isRefreshInFlight = false;
let refreshPending = false;
const REFRESH_DEBOUNCE_WINDOW_MS = 250;
const REFRESH_MAX_DEBOUNCE_MS = 1000;
let refreshWindowStartTime = null;

function scheduleCoalescedRefresh() {
    if (isRefreshInFlight) {
        refreshPending = true;
        return;
    }

    const now = Date.now();
    if (!refreshWindowStartTime) {
        refreshWindowStartTime = now;
    }

    // Trailing-edge debounce: reset timer on new event within the debounce window
    if (refreshTimer) {
        if (now - refreshWindowStartTime < REFRESH_MAX_DEBOUNCE_MS) {
            clearTimeout(refreshTimer);
        } else {
            // Under sustained events, do not delay indefinitely to prevent UI starvation
            return;
        }
    }

    refreshTimer = setTimeout(async () => {
        refreshTimer = null;
        refreshWindowStartTime = null;
        await executeCoalescedRefresh();
    }, REFRESH_DEBOUNCE_WINDOW_MS);
}

async function executeCoalescedRefresh() {
    if (isRefreshInFlight) {
        refreshPending = true;
        return;
    }
    isRefreshInFlight = true;
    refreshPending = false;
    try {
        await refreshDashboard();
    } finally {
        isRefreshInFlight = false;
        if (refreshPending) {
            refreshPending = false;
            scheduleCoalescedRefresh();
        }
    }
}

/* Server-Sent Events (SSE) Stream */
function initSSE() {
    if (typeof EventSource === "undefined") return;
    try {
        const source = new EventSource("/events");
        source.addEventListener("telemetry", () => scheduleCoalescedRefresh());
        source.addEventListener("incident", () => scheduleCoalescedRefresh());
        source.addEventListener("response", () => scheduleCoalescedRefresh());
        source.addEventListener("trust", () => scheduleCoalescedRefresh());
        source.addEventListener("simulation", () => scheduleCoalescedRefresh());
        source.addEventListener("alert", () => {
            scheduleCoalescedRefresh();
            refreshAdminAlerts();
            refreshAdminOverview();
        });
        source.onerror = () => {
            // Safe generic SSE error/reconnect handling without assuming error.status exists
        };
    } catch (err) {
        console.warn("SSE stream unavailable; polling active", err);
    }
}

// Window resize handler to re-draw canvas charts sharply
window.addEventListener("resize", () => {
    const liveRes = fetch("/api/telemetry", { cache: "no-store" })
        .then(r => r.json())
        .then(d => {
            if (d && d.rows) {
                renderHistorianChart(document.getElementById("trafficChart"), d.rows);
                renderEnergyChart(document.getElementById("energyChart"), d.rows);
                const threatCanvas = document.getElementById("threatChart");
                if (threatCanvas) renderThreatChart(threatCanvas, d.rows);
            }
        }).catch(() => {});

    fetch("/api/protocols", { cache: "no-store" })
        .then(r => r.json())
        .then(d => renderProtocolDonut(document.getElementById("protocolDonutChart"), d))
        .catch(() => {});
});

/* ==========================================================================
   ADMINISTRATIVE SECURITY LAYER: AUTH, RBAC, ALERTS, AUDIT, USERS
   ========================================================================== */

let currentAuthSession = null;
let currentAlertFilterMode = "ALL";
let cachedAdminAlerts = [];

async function checkAuthStatus() {
    try {
        const res = await fetch("/api/auth/status", { cache: "no-store" });
        if (res.ok) {
            const data = await res.json();
            currentAuthSession = data.authenticated ? data.user : null;
            renderAuthBadge(data);
        }
    } catch (e) {
        console.warn("Auth status fetch error:", e);
    }
}

function renderAuthBadge(authData) {
    const badge = document.getElementById("headerUserBadge");
    const userLabel = document.getElementById("headerUserLabel");
    const roleTag = document.getElementById("headerRoleTag");
    const dot = document.getElementById("headerAuthDot");
    const logoutBtn = document.getElementById("headerLogoutBtn");
    const addUserBtn = document.getElementById("btnOpenAddUserModal");
    const opNotice = document.getElementById("operatorUserNotice");
    const opAuditNotice = document.getElementById("operatorAuditNotice");

    if (!badge) return;

    if (authData.authenticated && authData.user) {
        const u = authData.user;
        if (userLabel) userLabel.textContent = u.username;
        if (roleTag) {
            roleTag.textContent = u.role;
            if (u.role === "ADMIN") {
                roleTag.style.color = "var(--cyan)";
                roleTag.style.borderColor = "rgba(56,189,248,0.4)";
                roleTag.style.background = "rgba(56,189,248,0.12)";
            } else {
                roleTag.style.color = "var(--amber)";
                roleTag.style.borderColor = "rgba(245,158,11,0.4)";
                roleTag.style.background = "rgba(245,158,11,0.12)";
            }
        }
        if (dot) dot.className = "indicator-dot green";
        if (logoutBtn) {
            logoutBtn.innerHTML = '🚪 <span>Logout</span>';
            logoutBtn.href = "/logout";
            logoutBtn.title = "Terminate Administrative Session";
        }

        // RBAC UI constraints
        const isAdmin = u.role === "ADMIN";
        if (addUserBtn) addUserBtn.style.display = isAdmin ? "inline-block" : "none";
        if (opNotice) opNotice.style.display = isAdmin ? "none" : "block";
        if (opAuditNotice) opAuditNotice.style.display = isAdmin ? "none" : "block";

        const btnAuditCsv = document.getElementById("btnExportAuditCsv");
        const btnAuditJson = document.getElementById("btnExportAuditJson");
        if (btnAuditCsv) btnAuditCsv.style.display = isAdmin ? "inline-flex" : "none";
        if (btnAuditJson) btnAuditJson.style.display = isAdmin ? "inline-flex" : "none";

    } else {
        if (userLabel) userLabel.textContent = "ANONYMOUS";
        if (roleTag) {
            roleTag.textContent = "UNAUTHENTICATED";
            roleTag.style.color = "var(--text-muted)";
            roleTag.style.borderColor = "var(--border-subtle)";
        }
        if (dot) dot.className = "indicator-dot amber";
        if (logoutBtn) {
            logoutBtn.innerHTML = '🔒 <span>Login</span>';
            logoutBtn.href = "/login";
            logoutBtn.title = "Authenticate Session";
        }
        if (addUserBtn) addUserBtn.style.display = "none";
        if (opNotice) opNotice.style.display = "block";
        if (opAuditNotice) opAuditNotice.style.display = "block";

        const btnAuditCsv = document.getElementById("btnExportAuditCsv");
        const btnAuditJson = document.getElementById("btnExportAuditJson");
        if (btnAuditCsv) btnAuditCsv.style.display = "none";
        if (btnAuditJson) btnAuditJson.style.display = "none";
    }
}

async function refreshAdminSection() {
    await checkAuthStatus();
    await Promise.all([
        refreshAdminOverview(),
        refreshAdminAlerts(),
        refreshAdminUsers(),
        refreshAdminAuditLogs()
    ]);
}

async function refreshAdminOverview() {
    try {
        const res = await fetch("/api/admin/overview", { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();

        // Update Overview Cards
        const u = data.user;
        const userEl = document.getElementById("adminOverviewUser");
        const roleBadge = document.getElementById("adminOverviewRoleBadge");
        const loginTimeEl = document.getElementById("adminOverviewLoginTime");
        if (userEl && u) userEl.textContent = u.username;
        if (roleBadge && u) {
            roleBadge.textContent = u.role;
            roleBadge.className = `tag ${u.role === "ADMIN" ? "tag-cyan" : "tag-amber"}`;
        }
        if (loginTimeEl && u) {
            loginTimeEl.textContent = `MFA: ${u.mfa_status || "SIMULATED VERIFIED"}`;
        }

        const k = data.kpis || {};
        const actAlertsEl = document.getElementById("adminOverviewActiveAlerts");
        const unackBadge = document.getElementById("adminOverviewUnackBadge");
        const totalAlertsEl = document.getElementById("adminOverviewTotalAlerts");
        if (actAlertsEl) actAlertsEl.textContent = k.active_alerts ?? 0;
        if (unackBadge) {
            unackBadge.textContent = `${k.unacknowledged_alerts ?? 0} UNACK`;
            unackBadge.style.display = (k.unacknowledged_alerts > 0) ? "inline-block" : "none";
        }
        if (totalAlertsEl) totalAlertsEl.textContent = k.total_alerts ?? 0;

        const openIncEl = document.getElementById("adminOverviewOpenIncidents");
        const critBadge = document.getElementById("adminOverviewCritBadge");
        if (openIncEl) openIncEl.textContent = k.open_incidents ?? 0;
        if (critBadge) {
            critBadge.textContent = `${k.critical_incidents ?? 0} CRITICAL`;
            critBadge.style.display = (k.critical_incidents > 0) ? "inline-block" : "none";
        }

        // Mini Audit Log
        renderMiniAuditLogs(data.recent_audits || []);
    } catch (e) {
        console.warn("Admin overview error:", e);
    }
}

function renderMiniAuditLogs(audits) {
    const tbody = document.getElementById("adminOverviewAuditTbody");
    if (!tbody) return;
    if (!audits.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 10px;">No audit events recorded yet.</td></tr>';
        return;
    }
    tbody.innerHTML = audits.slice(0, 5).map(a => {
        const isSuccess = a.result === "SUCCESS";
        const resultColor = isSuccess ? "var(--green)" : (a.result === "DENIED" ? "var(--amber)" : "var(--red)");
        const timeFormatted = a.timestamp ? a.timestamp.substring(11, 19) : "--:--:--";
        return `<tr>
            <td style="font-family: var(--font-mono); color: var(--text-muted);">${timeFormatted}</td>
            <td style="font-weight: 600;">${escapeHtml(a.username)}</td>
            <td><span class="tag" style="font-size: 9px;">${escapeHtml(a.role)}</span></td>
            <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyan);">${escapeHtml(a.action)}</td>
            <td style="color: var(--text-muted);">${escapeHtml(a.resource || "system")}</td>
            <td><span class="tag" style="color: ${resultColor}; border-color: ${resultColor}44; font-size: 9px;">${escapeHtml(a.result)}</span></td>
            <td style="color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(a.details)}">${escapeHtml(a.details)}</td>
        </tr>`;
    }).join("");
}

async function refreshAdminAlerts() {
    try {
        const res = await fetch("/api/admin/alerts?limit=200", { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        cachedAdminAlerts = data.alerts || [];

        // Update counts
        const allCount = cachedAdminAlerts.length;
        const unackCount = cachedAdminAlerts.filter(a => a.acknowledgement_state === "UNACKNOWLEDGED").length;
        const activeCount = cachedAdminAlerts.filter(a => a.status === "ACTIVE").length;
        const resolvedCount = cachedAdminAlerts.filter(a => a.status === "RESOLVED" || a.status === "CLOSED").length;

        const cAll = document.getElementById("countAlertsAll");
        const cUnack = document.getElementById("countAlertsUnack");
        const cActive = document.getElementById("countAlertsActive");
        const cResolved = document.getElementById("countAlertsResolved");
        const sbBadge = document.getElementById("sidebarAlertCounter");

        if (cAll) cAll.textContent = allCount;
        if (cUnack) cUnack.textContent = unackCount;
        if (cActive) cActive.textContent = activeCount;
        if (cResolved) cResolved.textContent = resolvedCount;

        if (sbBadge) {
            sbBadge.textContent = unackCount;
            sbBadge.style.display = unackCount > 0 ? "inline-block" : "none";
        }

        renderFilteredAlerts();
    } catch (e) {
        console.warn("Admin alerts error:", e);
    }
}

function filterAdminAlerts(mode) {
    currentAlertFilterMode = mode;
    ["filterAlertsAll", "filterAlertsUnack", "filterAlertsActive", "filterAlertsResolved"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove("active");
    });
    const map = {
        "ALL": "filterAlertsAll",
        "UNACK": "filterAlertsUnack",
        "ACTIVE": "filterAlertsActive",
        "RESOLVED": "filterAlertsResolved"
    };
    const activeEl = document.getElementById(map[mode]);
    if (activeEl) activeEl.classList.add("active");
    renderFilteredAlerts();
}

function renderFilteredAlerts() {
    const tbody = document.getElementById("adminAlertsTableBody");
    if (!tbody) return;

    let filtered = cachedAdminAlerts;
    if (currentAlertFilterMode === "UNACK") {
        filtered = cachedAdminAlerts.filter(a => a.acknowledgement_state === "UNACKNOWLEDGED");
    } else if (currentAlertFilterMode === "ACTIVE") {
        filtered = cachedAdminAlerts.filter(a => a.status === "ACTIVE");
    } else if (currentAlertFilterMode === "RESOLVED") {
        filtered = cachedAdminAlerts.filter(a => a.status === "RESOLVED" || a.status === "CLOSED");
    }

    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 20px;">
            No alerts matching filter '${currentAlertFilterMode}'.
        </td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(a => {
        const sev = (a.severity || "MEDIUM").toUpperCase();
        let sevColor = "var(--cyan)";
        let sevBg = "rgba(56,189,248,0.12)";
        if (sev === "CRITICAL") { sevColor = "var(--red)"; sevBg = "rgba(244,63,94,0.18)"; }
        else if (sev === "HIGH") { sevColor = "var(--amber)"; sevBg = "rgba(245,158,11,0.16)"; }
        else if (sev === "LOW") { sevColor = "var(--text-muted)"; sevBg = "rgba(100,116,139,0.15)"; }

        const isUnack = a.acknowledgement_state === "UNACKNOWLEDGED";
        const ackColor = isUnack ? "var(--amber)" : "var(--green)";
        const ackText = isUnack ? "UNACKNOWLEDGED" : `ACK (${escapeHtml(a.acknowledged_by || "user")})`;

        const timeFormatted = a.timestamp ? a.timestamp.substring(11, 19) : "--:--:--";
        const confPercent = (Number(a.confidence || 0.95) * 100).toFixed(1) + "%";

        const ackButton = isUnack ?
            `<button type="button" class="btn-sim-action btn-ack" data-alert-id="${escapeHtml(a.alert_id)}" onclick="acknowledgeAlert('${a.alert_id}')" style="padding: 3px 8px; font-size: 10px; background: rgba(245,158,11,0.15); border: 1px solid rgba(245,158,11,0.5); color: var(--amber); border-radius: 3px; cursor: pointer;">ACKNOWLEDGE</button>` :
            `<span style="font-size: 10px; color: var(--green);">✓ ACKNOWLEDGED</span>`;

        return `<tr>
            <td><span class="tag" style="color:${sevColor}; background:${sevBg}; border-color:${sevColor}66; font-weight:700;">${sev}</span></td>
            <td style="font-family: var(--font-mono); font-weight:600; color:var(--text-primary);">${escapeHtml(a.alert_id)}</td>
            <td style="font-family: var(--font-mono); color:var(--text-muted);">${timeFormatted}</td>
            <td><strong style="color:var(--text-primary);">${escapeHtml(a.attack_type)}</strong></td>
            <td style="font-family: var(--font-mono); color:var(--text-secondary);">${escapeHtml(a.device_id || a.target)}</td>
            <td style="font-family: var(--font-mono);">${confPercent}</td>
            <td><span class="tag tag-lifecycle" style="font-size: 9px;">${escapeHtml(a.lifecycle_state)}</span></td>
            <td><span class="tag" style="font-size: 9px; color:var(--cyan); border-color:rgba(56,189,248,0.3);">${escapeHtml(a.current_action)}</span></td>
            <td><span class="tag" style="color:${ackColor}; border-color:${ackColor}44; font-size:9px;">${ackText}</span></td>
            <td style="white-space: nowrap;">
                <div style="display: flex; gap: 4px; align-items: center;">
                    ${ackButton}
                    <a href="#sec-incidents" onclick="highlightIncidentInJournal('${a.incident_id}')" style="padding: 3px 6px; font-size: 10px; background: var(--bg-card); border: 1px solid var(--border-subtle); color: var(--text-secondary); text-decoration: none; border-radius: 3px;">VIEW INCIDENT</a>
                </div>
            </td>
        </tr>`;
    }).join("");
}

async function acknowledgeAlert(alertId) {
    try {
        const res = await fetch(`/api/admin/alerts/${alertId}/acknowledge`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        if (res.ok) {
            await refreshAdminAlerts();
            await refreshAdminOverview();
            await refreshAdminAuditLogs();
        } else {
            const err = await res.json();
            alert(`Unable to acknowledge alert: ${err.error || "Permission denied"}`);
        }
    } catch (e) {
        console.error("Acknowledge alert error:", e);
    }
}

function highlightIncidentInJournal(incidentId) {
    const el = document.getElementById("sec-incidents");
    if (el) {
        el.scrollIntoView({ behavior: "smooth" });
        setTimeout(() => {
            const rows = document.querySelectorAll("#incidentsTableBody tr");
            rows.forEach(r => {
                if (r.textContent.includes(incidentId)) {
                    r.style.outline = "2px solid var(--cyan)";
                    r.style.background = "rgba(56, 189, 248, 0.15)";
                    setTimeout(() => {
                        r.style.outline = "";
                        r.style.background = "";
                    }, 3500);
                }
            });
        }, 400);
    }
}

async function refreshAdminUsers() {
    const tbody = document.getElementById("adminUsersTableBody");
    if (!tbody) return;

    if (!currentAuthSession) {
        await checkAuthStatus();
    }

    if (!currentAuthSession || currentAuthSession.role !== "ADMIN") {
        tbody.innerHTML = `<tr>
            <td>USR-OPERATOR-01</td>
            <td><strong>operator</strong></td>
            <td><span class="tag" style="color:var(--amber); border-color:rgba(245,158,11,0.4);">OPERATOR</span></td>
            <td><span class="tag" style="color:var(--green);">ACTIVE</span></td>
            <td><span class="tag" style="color:var(--amber);">SIMULATED MFA</span></td>
            <td style="font-family:var(--font-mono); color:var(--text-muted);">2026-09-15</td>
            <td style="font-family:var(--font-mono); color:var(--text-muted);">Recent</td>
            <td style="color:var(--text-muted); font-size:10px;">READ-ONLY VIEW</td>
        </tr>`;
        return;
    }

    try {
        const res = await fetch("/api/admin/users", { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        const users = data.users || [];

        if (!users.length) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:14px;">No users registered.</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(u => {
            const isActive = u.status === "ACTIVE";
            const roleColor = u.role === "ADMIN" ? "var(--cyan)" : "var(--amber)";
            const toggleAction = isActive ? "DISABLED" : "ACTIVE";
            const toggleBtnText = isActive ? "Disable" : "Enable";
            const toggleBtnStyle = isActive ? "background:rgba(244,63,94,0.1); border-color:rgba(244,63,94,0.3); color:var(--red);" : "background:rgba(16,185,129,0.1); border-color:rgba(16,185,129,0.3); color:var(--green);";

            return `<tr>
                <td style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${escapeHtml(u.user_id)}</td>
                <td style="font-weight:700; color:var(--text-primary);">${escapeHtml(u.username)}</td>
                <td><span class="tag" style="color:${roleColor}; border-color:${roleColor}55;">${escapeHtml(u.role)}</span></td>
                <td><span class="tag" style="color:${isActive ? 'var(--green)' : 'var(--red)'}; border-color:${isActive ? 'var(--green)' : 'var(--red)'}44;">${escapeHtml(u.status)}</span></td>
                <td><span class="tag" style="color:var(--amber); border-color:rgba(245,158,11,0.3); font-size:9px;">${escapeHtml(u.mfa_status || "SIMULATED")}</span></td>
                <td style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${u.created_at ? u.created_at.substring(0, 10) : "--"}</td>
                <td style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${u.last_login ? u.last_login.substring(11, 19) : "Never"}</td>
                <td>
                    <button type="button" onclick="toggleUserStatus('${u.user_id}', '${toggleAction}')" style="padding:2px 8px; font-size:10px; border-radius:3px; cursor:pointer; ${toggleBtnStyle}">
                        ${toggleBtnText}
                    </button>
                </td>
            </tr>`;
        }).join("");
    } catch (e) {
        console.warn("Admin users error:", e);
    }
}

function toggleAddUserForm() {
    const el = document.getElementById("addUserFormContainer");
    if (el) el.style.display = (el.style.display === "none" || !el.style.display) ? "block" : "none";
}

async function submitCreateUser() {
    const user = document.getElementById("newLabUsername").value.trim();
    const pass = document.getElementById("newLabPassword").value;
    const role = document.getElementById("newLabRole").value;
    const msg = document.getElementById("addUserMsg");

    if (!user || !pass) {
        if (msg) {
            msg.style.display = "block";
            msg.style.color = "var(--red)";
            msg.textContent = "Username and password required.";
        }
        return;
    }

    try {
        const res = await fetch("/api/admin/users", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: user, password: pass, role: role })
        });
        const data = await res.json();
        if (res.ok) {
            document.getElementById("newLabUsername").value = "";
            document.getElementById("newLabPassword").value = "";
            toggleAddUserForm();
            await refreshAdminUsers();
            await refreshAdminOverview();
            await refreshAdminAuditLogs();
        } else {
            if (msg) {
                msg.style.display = "block";
                msg.style.color = "var(--red)";
                msg.textContent = data.error || "User creation failed.";
            }
        }
    } catch (e) {
        console.error("Create user error:", e);
    }
}

async function toggleUserStatus(userId, newStatus) {
    try {
        const res = await fetch(`/api/admin/users/${userId}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
        });
        if (res.ok) {
            await refreshAdminUsers();
            await refreshAdminOverview();
            await refreshAdminAuditLogs();
        } else {
            const err = await res.json();
            alert(`Status change failed: ${err.error || "Permission denied"}`);
        }
    } catch (e) {
        console.error("Toggle user status error:", e);
    }
}

let cachedAuditRecords = [];

async function checkAuditIntegrity() {
    const badge = document.getElementById("auditIntegrityBadge");
    if (!badge) return;
    try {
        const res = await fetch("/api/admin/audit/integrity", { cache: "no-store" });
        if (!res.ok) {
            if (res.status === 403) {
                badge.style.display = "none";
            } else {
                badge.textContent = "LEDGER INTEGRITY: ERROR";
                badge.className = "tag tag-tamper";
                badge.style.color = "var(--red)";
                badge.style.borderColor = "rgba(239,68,68,0.5)";
                badge.style.background = "rgba(239,68,68,0.15)";
            }
            return;
        }
        const data = await res.json();
        badge.style.display = "inline-flex";
        if (data.valid) {
            const countStr = typeof data.count === "number" ? ` (${data.count} records)` : "";
            badge.textContent = `LEDGER VERIFIED (SHA-256)${countStr}`;
            badge.className = "tag tag-verified";
            badge.style.color = "var(--green)";
            badge.style.borderColor = "rgba(16,185,129,0.4)";
            badge.style.background = "rgba(16,185,129,0.15)";
        } else {
            badge.textContent = "LEDGER TAMPER DETECTED (SHA-256)";
            badge.className = "tag tag-tamper";
            badge.style.color = "var(--red)";
            badge.style.borderColor = "rgba(239,68,68,0.5)";
            badge.style.background = "rgba(239,68,68,0.2)";
        }
    } catch (e) {
        console.warn("Audit integrity error:", e);
    }
}

async function refreshAdminAuditLogs() {
    const tbody = document.getElementById("adminAuditTableBody");
    if (!tbody) return;

    checkAuditIntegrity();

    try {
        const res = await fetch("/api/admin/audit?limit=100", { cache: "no-store" });
        if (!res.ok) {
            if (res.status === 403) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:14px;">Audit log access is restricted to ADMIN role. Operator access is denied (HTTP 403).</td></tr>';
            }
            return;
        }
        const data = await res.json();
        cachedAuditRecords = data.audit_events || [];
        renderAuditTable(cachedAuditRecords);
    } catch (e) {
        console.warn("Audit logs error:", e);
    }
}

function renderAuditTable(records) {
    const tbody = document.getElementById("adminAuditTableBody");
    if (!tbody) return;

    if (!records.length) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:16px;">No administrative audit records logged yet.</td></tr>';
        return;
    }

    tbody.innerHTML = records.map(a => {
        const isSuccess = a.result === "SUCCESS";
        const resultColor = isSuccess ? "var(--green)" : (a.result === "DENIED" ? "var(--amber)" : "var(--red)");
        const timeFormatted = a.timestamp ? a.timestamp.substring(0, 19).replace("T", " ") : "--";

        return `<tr>
            <td style="font-family: var(--font-mono); font-size:10px; color:var(--cyan);">${escapeHtml(a.event_id)}</td>
            <td style="font-family: var(--font-mono); font-size:10px; color:var(--text-muted);">${timeFormatted}</td>
            <td style="font-weight:700; color:var(--text-primary);">${escapeHtml(a.username)}</td>
            <td><span class="tag" style="font-size:9px;">${escapeHtml(a.role)}</span></td>
            <td style="font-family: var(--font-mono); font-weight:700; color:var(--cyan);">${escapeHtml(a.action)}</td>
            <td style="color:var(--text-muted);">${escapeHtml(a.resource || "system")}</td>
            <td><span class="tag" style="color:${resultColor}; border-color:${resultColor}44; font-size:9px;">${escapeHtml(a.result)}</span></td>
            <td style="color:var(--text-secondary); max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(a.details)}">${escapeHtml(a.details)}</td>
        </tr>`;
    }).join("");
}

function filterAuditTable() {
    const query = (document.getElementById("auditSearchInput")?.value || "").toLowerCase();
    if (!query) {
        renderAuditTable(cachedAuditRecords);
        return;
    }
    const filtered = cachedAuditRecords.filter(a => {
        return (a.action && a.action.toLowerCase().includes(query)) ||
               (a.username && a.username.toLowerCase().includes(query)) ||
               (a.details && a.details.toLowerCase().includes(query)) ||
               (a.resource && a.resource.toLowerCase().includes(query));
    });
    renderAuditTable(filtered);
}

// Expose Admin Security Layer functions to window
window.refreshAdminSection = refreshAdminSection;
window.refreshAdminOverview = refreshAdminOverview;
window.refreshAdminAlerts = refreshAdminAlerts;
window.refreshAdminUsers = refreshAdminUsers;
window.refreshAdminAuditLogs = refreshAdminAuditLogs;
window.filterAdminAlerts = filterAdminAlerts;
window.acknowledgeAlert = acknowledgeAlert;
window.toggleAddUserForm = toggleAddUserForm;
window.submitCreateUser = submitCreateUser;
window.toggleUserStatus = toggleUserStatus;
window.filterAuditTable = filterAuditTable;
window.refreshAuditLogs = refreshAdminAuditLogs;
window.checkAuditIntegrity = checkAuditIntegrity;
window.scheduleCoalescedRefresh = scheduleCoalescedRefresh;
window.executeCoalescedRefresh = executeCoalescedRefresh;
window.__refreshCoalesce = {
    get timer() { return refreshTimer; },
    get inFlight() { return isRefreshInFlight; },
    get pending() { return refreshPending; },
    schedule: scheduleCoalescedRefresh,
    execute: executeCoalescedRefresh,
};

// Boot HMI
initSidebarNavigation();
checkAuthStatus();
refreshDashboard();
setInterval(refreshDashboard, 3500);
initSSE();

