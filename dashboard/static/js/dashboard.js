/* ==========================================================================
   AEGIS-OT • INDUSTRIAL SOC & OT SECURITY OPERATIONS HMI
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
function updateSummary(summary) {
    if (!summary || typeof summary !== "object") return;

    const pred = summary.latest_prediction || "NORMAL";
    const isAttack = pred === "ATTACK";
    const ddosProb = Number(summary.latest_ddos_probability ?? (isAttack ? 0.99 : 0.05));
    const pps = Number(summary.latest_packet_rate ?? 18.0);
    const byteRate = Number(summary.latest_bytes_per_second ?? 4140.0);
    const secAction = summary.latest_security_action || (isAttack ? "BLOCK" : "ALERT");
    const mitAction = summary.latest_mitigation_action || (isAttack ? "BLOCK" : "NONE");
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
    if (threatStatusEl) threatStatusEl.textContent = isAttack ? "ATTACK" : "CLEAR";
    if (threatMetaEl) threatMetaEl.textContent = isAttack ? "DDoS Attack Vector" : "Baseline Normal";
    if (classificationEl) classificationEl.textContent = pred;
    if (kpiRiskTag) {
        kpiRiskTag.textContent = isAttack ? "CRITICAL" : "CLEAR";
        kpiRiskTag.className = `kpi-status-tag ${isAttack ? "tag-red" : "tag-green"}`;
    }
    if (headerThreatPill) {
        headerThreatPill.className = `threat-state-pill ${isAttack ? "attack" : "clear"}`;
    }

    // Card 3: Plant State
    const plantStateVal = document.getElementById("plantStateVal");
    if (plantStateVal) {
        plantStateVal.textContent = isAttack ? "ATTACKED" : "CLEAR";
        plantStateVal.style.color = isAttack ? "var(--red)" : "var(--green)";
    }

    // Card 4: Mitigation State
    const securityActionEl = document.getElementById("securityAction");
    const mitigationActionEl = document.getElementById("mitigationAction");
    if (securityActionEl) securityActionEl.textContent = secAction;
    if (mitigationActionEl) {
        mitigationActionEl.textContent = mitAction;
        mitigationActionEl.style.color = isAttack ? "var(--red)" : "var(--cyan)";
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
    const isRecovering = summary.lifecycle_state === "RECOVERING";

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
        if (target) target.textContent = "GATEWAY-01";
        if (severity) {
            severity.textContent = "MEDIUM";
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
 * Primary Chart #1: Historian • Packets / Second
 */
function renderHistorianChart(canvas, rows) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padLeft = 45;
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
        ctx.fillText("Awaiting live telemetry windows...", width / 2, height / 2);
        return;
    }

    const rates = dataPoints.map(r => Number(r.packets_per_second || r.packet_rate || 0));
    const maxVal = Math.max(60, ...rates) * 1.15;

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

    // Draw Series 1: Legitimate OT Baseline (~20 pps) Area
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const val = Math.min(Number(r.packets_per_second || r.packet_rate || 0), 20.0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + (dataPoints.length - 1) * xStep, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();
    ctx.fillStyle = "rgba(16, 185, 129, 0.15)";
    ctx.fill();

    // Draw Legitimate Baseline Line
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const val = Math.min(Number(r.packets_per_second || r.packet_rate || 0), 20.0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#10b981";
    ctx.lineWidth = 1.8;
    ctx.stroke();

    // Draw Series 2: Attack Surge (Values above 20 pps)
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
    ctx.fillStyle = "rgba(244, 63, 94, 0.18)";
    ctx.fill();

    // Draw Attack Surge Line
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const val = Number(r.packets_per_second || r.packet_rate || 0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#f43f5e";
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // Draw Series 3: Simulated Throttle / Drop Line
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = "#f59e0b";
    ctx.lineWidth = 1.6;
    dataPoints.forEach((r, idx) => {
        const isMitigated = ["BLOCK", "RATE_LIMIT", "ISOLATE"].includes(r.security_action || r.mitigation_action || "");
        const raw = Number(r.packets_per_second || r.packet_rate || 0);
        const val = isMitigated ? Math.max(0, raw - 20.0) : 0;
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.setLineDash([]);

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

    let mix = (protocolsData && protocolsData.mix) ? protocolsData.mix : { "UDP": 212, "TCP": 20, "ICMPV6": 9, "MQTT": 8 };
    const total = Object.values(mix).reduce((a, b) => a + Number(b), 0) || 1;

    // Update Pills
    if (mix["UDP"] !== undefined) {
        const el = document.getElementById("protoCountUDP");
        if (el) el.textContent = `${((mix["UDP"] / total) * 100).toFixed(0)}% (${mix["UDP"]})`;
    }
    if (mix["TCP"] !== undefined) {
        const el = document.getElementById("protoCountTCP");
        if (el) el.textContent = `${((mix["TCP"] / total) * 100).toFixed(0)}% (${mix["TCP"]})`;
    }
    const icmpCount = (mix["ICMP"] || 0) + (mix["ICMPV6"] || 0);
    const elIcmp = document.getElementById("protoCountICMP");
    if (elIcmp) elIcmp.textContent = `${((icmpCount / total) * 100).toFixed(0)}% (${icmpCount})`;

    const mqttCount = mix["MQTT"] || 8;
    const elMqtt = document.getElementById("protoCountMQTT");
    if (elMqtt) elMqtt.textContent = `${((mqttCount / total) * 100).toFixed(0)}% (${mqttCount})`;

    // Determine Primary Protocol
    let maxK = "UDP";
    let maxV = 0;
    for (const [k, v] of Object.entries(mix)) {
        if (Number(v) > maxV) { maxV = Number(v); maxK = k; }
    }
    const centerVal = document.getElementById("donutPrimaryProto");
    const centerPct = document.getElementById("donutPrimaryPct");
    if (centerVal) centerVal.textContent = maxK === "ICMPV6" ? "ICMP" : maxK;
    if (centerPct) centerPct.textContent = `${((maxV / total) * 100).toFixed(0)}%`;

    // Draw Crisp Doughnut Slices
    const centerX = width / 2;
    const centerY = height / 2;
    const outerRadius = Math.min(centerX, centerY) - 8;
    const innerRadius = outerRadius * 0.72;

    const palette = {
        "UDP": "#38bdf8",
        "TCP": "#818cf8",
        "ICMP": "#f43f5e",
        "ICMPV6": "#f43f5e",
        "MQTT": "#10b981",
        "OTHER": "#f59e0b"
    };

    let startAngle = -Math.PI / 2;

    Object.entries(mix).forEach(([proto, count]) => {
        const sliceAngle = (Number(count) / total) * (Math.PI * 2);
        const endAngle = startAngle + sliceAngle;

        ctx.beginPath();
        ctx.arc(centerX, centerY, outerRadius, startAngle, endAngle);
        ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = palette[proto.toUpperCase()] || "#a855f7";
        ctx.fill();

        ctx.lineWidth = 2;
        ctx.strokeStyle = "#0d1627";
        ctx.stroke();

        startAngle = endAngle;
    });
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
        const isAuth = dev.authenticated;
        const isAllow = isAuth && dev.role !== "untrusted" && dev.trust_score >= 40.0;
        const trustColor = dev.trust_score >= 70 ? "var(--green)" : (dev.trust_score >= 40 ? "var(--amber)" : "var(--red)");
        
        return `
            <tr>
                <td><strong>${escapeHtml(dev.identity)}</strong></td>
                <td style="text-transform: capitalize;">${escapeHtml(dev.role)}</td>
                <td><span class="iam-badge ${isAuth ? 'iam-allow' : 'iam-deny'}">${isAuth ? 'AUTH' : 'FAILED'}</span></td>
                <td><span class="iam-badge ${isAllow ? 'iam-allow' : 'iam-deny'}">${isAllow ? 'ALLOW' : 'DENY'}</span></td>
                <td><strong style="color: ${trustColor}; font-family: var(--font-mono);">${dev.trust_score.toFixed(1)}</strong></td>
            </tr>
        `;
    }).join("");
}


/* ==========================================================================
   8. INCIDENT LIFECYCLE (HORIZONTAL 7-STEP STEPPER)
   ========================================================================== */
function updateLifecycle(lifecycle, summary) {
    const rawState = (lifecycle ? lifecycle.lifecycle_state : (summary.lifecycle_state || "NORMAL")).toUpperCase();
    const state = rawState === "NORMAL" ? "NORMAL" : rawState;
    const isNormal = state === "NORMAL" || state === "IDLE";

    const stateBadge = document.getElementById("lifecycleState");
    const stageText = document.getElementById("lifecycleStage");
    const recoveryText = document.getElementById("lifecycleRecovery");
    const normalBadge = document.getElementById("lifecycleNormalBadge");

    if (stateBadge) {
        stateBadge.textContent = state;
        stateBadge.style.color = isNormal ? "var(--green)" : "var(--red)";
    }
    if (stageText) {
        stageText.textContent = (lifecycle && lifecycle.lifecycle_stage ? lifecycle.lifecycle_stage : (isNormal ? "BASELINE OBSERVATION" : "AUTONOMOUS RESPONSE")).replace(/_/g, " ");
    }
    if (recoveryText) {
        recoveryText.textContent = summary.recovery_state || (isNormal ? "MONITORING" : "CONTAINED_IN_SOFTWARE");
        recoveryText.style.color = isNormal ? "var(--green)" : "var(--amber)";
    }

    if (normalBadge) {
        normalBadge.classList.toggle("active", isNormal);
    }

    // Horizontal 7-Step Progression
    const stepOrder = ["DETECTED", "ANALYZING", "RESPONDING", "CONTAINED", "RECOVERING", "RESOLVED", "CLOSED"];
    const currentIdx = stepOrder.indexOf(state);

    stepOrder.forEach((step, idx) => {
        const id = `stepNode${step.charAt(0) + step.slice(1).toLowerCase()}`;
        const node = document.getElementById(id);
        if (!node) return;

        node.className = "step-node";
        if (isNormal) {
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
}


/* ==========================================================================
   9. INCIDENT JOURNAL & THREAT EVENTS
   ========================================================================== */
function updateIncidents(incidents) {
    const table = document.getElementById("incidentsTable");
    const countEl = document.getElementById("incidentCount");
    const activeIdEl = document.getElementById("activeIncId");
    const actionControls = document.getElementById("incidentActionControls");

    if (countEl) countEl.textContent = incidents ? incidents.length : 0;

    if (!incidents || !incidents.length) {
        if (table) {
            table.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 18px;">No active or historical incidents recorded in historian.</td></tr>`;
        }
        if (activeIdEl) activeIdEl.textContent = "NONE (BASELINE)";
        if (actionControls) actionControls.innerHTML = "";
        return;
    }

    const latest = incidents[0];
    const isLatestActive = !["RESOLVED", "CLOSED"].includes(latest.lifecycle_state);
    if (activeIdEl) {
        activeIdEl.textContent = isLatestActive ? latest.incident_id : `${latest.incident_id} (${latest.lifecycle_state})`;
    }

    // Operator Action Quick Controls
    if (actionControls) {
        const st = latest.lifecycle_state;
        if (["CONTAINED", "RECOVERING", "RESPONDING", "DETECTED"].includes(st)) {
            actionControls.innerHTML = `<button class="btn-sim-action btn-recover" type="button" onclick="transitionIncidentState('${latest.incident_id}', 'RESOLVED')">Resolve Incident</button>`;
        } else if (st === "RESOLVED") {
            actionControls.innerHTML = `<button class="btn-sim-action" type="button" onclick="transitionIncidentState('${latest.incident_id}', 'CLOSED')">Close Incident</button>`;
        } else {
            actionControls.innerHTML = "";
        }
    }

    if (!table) return;
    table.innerHTML = incidents.map(inc => {
        const state = inc.lifecycle_state || "UNKNOWN";
        const isClosed = ["RESOLVED", "CLOSED"].includes(state);
        const sev = inc.severity || "MEDIUM";
        const sevClass = (sev === "CRITICAL" || sev === "HIGH") ? "color: var(--red);" : "color: var(--green);";
        const dt = (inc.updated_at || inc.created_at || "").replace("T", " ").split(".")[0];

        let actionBtn = "—";
        if (["CONTAINED", "RECOVERING", "RESPONDING", "DETECTED"].includes(state)) {
            actionBtn = `<button class="btn-sim-action btn-recover" type="button" onclick="transitionIncidentState('${inc.incident_id}', 'RESOLVED')">Resolve</button>`;
        } else if (state === "RESOLVED") {
            actionBtn = `<button class="btn-sim-action" type="button" onclick="transitionIncidentState('${inc.incident_id}', 'CLOSED')">Close</button>`;
        }

        return `
            <tr>
                <td style="font-family: monospace; color: var(--cyan);">${escapeHtml(inc.incident_id)}</td>
                <td style="font-size: 10px; color: var(--text-muted);">${dt}</td>
                <td><strong>${escapeHtml(inc.device_id || "10.42.0.250")}</strong></td>
                <td>${escapeHtml(inc.attack_type || "udp_flood")}</td>
                <td><strong style="${sevClass}">${sev}</strong></td>
                <td style="font-family: monospace;">${inc.confidence ? (inc.confidence * 100).toFixed(0) + "%" : "—"}</td>
                <td><span class="iam-badge ${isClosed ? 'iam-allow' : 'iam-deny'}">${state}</span></td>
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

window.stopCurrentSimulation = async function() {
    const banner = document.getElementById("simStatusBanner");
    const detail = document.getElementById("simStatusDetail");
    try {
        await fetch("/api/simulations/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });
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
    window.currentAutoResponse = !window.currentAutoResponse;
    const mode = window.currentAutoResponse ? "DRY_RUN" : "MANUAL";
    const textEl = document.getElementById("btnResponseModeText");
    const btnEl = document.getElementById("btnResponseMode");

    try {
        const res = await fetch("/api/settings/mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: mode, auto: window.currentAutoResponse })
        });
        if (res.ok) {
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
        if (res.ok) {
            refreshDashboard();
        }
    } catch (e) {
        console.error("Manual action failed:", e);
    }
};

window.transitionIncidentState = async function(incidentId, targetState) {
    try {
        await fetch(`/api/incidents/${incidentId}/transition`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ state: targetState, actor: "operator", note: "Operator transitioned state via HMI" })
        });
        refreshDashboard();
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
        const statusRes = await fetch("/api/status", { cache: "no-store" });
        if (statusRes.ok) {
            const status = await statusRes.json();
            const sysStatus = document.getElementById("systemStatus");
            const dot = document.getElementById("statusDot");
            const isOnline = status.status === "ONLINE";
            if (sysStatus) sysStatus.textContent = isOnline ? "ONLINE" : "NO DATA";
            if (dot) {
                dot.classList.toggle("online", isOnline);
                dot.classList.toggle("offline", !isOnline);
            }
            updateSummary(status.summary || {});
        }

        // 2. Telemetry & Time-Series Charts
        const liveRes = await fetch("/api/telemetry", { cache: "no-store" });
        let liveRows = [];
        if (liveRes.ok) {
            const liveData = await liveRes.json();
            liveRows = liveData.rows || [];
            if (liveRows.length) {
                const latest = liveRows[liveRows.length - 1];
                updateDetection(latest);
                updateExplainability(latest.explainability_context);
                updateLifecycle(latest.lifecycle_context, liveData);
                updateSampleFlows(liveRows);
            }
            renderHistorianChart(document.getElementById("trafficChart"), liveRows);
            renderThreatChart(document.getElementById("threatChart"), liveRows);
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
        const incRes = await fetch("/api/incidents", { cache: "no-store" });
        if (incRes.ok) {
            const incData = await incRes.json();
            updateIncidents(incData.incidents);
        }

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

/* Server-Sent Events (SSE) Stream */
function initSSE() {
    if (typeof EventSource === "undefined") return;
    try {
        const source = new EventSource("/events");
        source.addEventListener("telemetry", () => refreshDashboard());
        source.addEventListener("incident", () => refreshDashboard());
        source.addEventListener("response", () => refreshDashboard());
        source.addEventListener("trust", () => refreshDashboard());
        source.addEventListener("simulation", () => refreshDashboard());
        source.onerror = () => {
            // Reconnect handled automatically by EventSource
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
                renderThreatChart(document.getElementById("threatChart"), d.rows);
            }
        }).catch(() => {});

    fetch("/api/protocols", { cache: "no-store" })
        .then(r => r.json())
        .then(d => renderProtocolDonut(document.getElementById("protocolDonutChart"), d))
        .catch(() => {});
});

// Boot HMI
refreshDashboard();
setInterval(refreshDashboard, 3500);
initSSE();
