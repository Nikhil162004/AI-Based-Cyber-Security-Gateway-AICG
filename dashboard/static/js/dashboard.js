let trafficChart = null;
let threatChart = null;


function percent(value) {
    return `${(Number(value || 0) * 100).toFixed(1)}%`;
}


function number(value, digits = 1) {
    return Number(value || 0).toLocaleString(
        undefined,
        {
            maximumFractionDigits: digits
        }
    );
}


function setThreatState(isThreat) {
    const threatStatus = document.getElementById("threatStatus");
    const classification = document.getElementById("classification");
    const securityAction = document.getElementById("securityAction");
    const mitigationAction = document.getElementById("mitigationAction");

    threatStatus.classList.toggle("status-normal", !isThreat);
    threatStatus.classList.toggle("status-threat", isThreat);

    classification.classList.toggle("normal", !isThreat);
    classification.classList.toggle("threat", isThreat);

    securityAction.classList.toggle("action-normal", !isThreat);
    securityAction.classList.toggle("action-threat", isThreat);

    mitigationAction.classList.toggle("action-normal", !isThreat);
    mitigationAction.classList.toggle("action-threat", isThreat);
}


function updateSummary(summary) {
    const prediction = summary.latest_prediction;
    const isThreat = prediction !== "NORMAL";

    document.getElementById("packetRate").textContent =
        number(summary.latest_packet_rate);

    document.getElementById("throughput").textContent =
        number(summary.latest_bytes_per_second);

    document.getElementById("ddosProbability").textContent =
        (Number(summary.latest_ddos_probability || 0) * 100).toFixed(1);

    document.getElementById("threatStatus").textContent =
        prediction;

    document.getElementById("threatMeta").textContent =
        isThreat
            ? "Threat classification active"
            : "No active threat detected";

    document.getElementById("securityAction").textContent =
        summary.latest_security_action;

    document.getElementById("mitigationAction").textContent =
        summary.latest_mitigation_action;

    setThreatState(isThreat);
}


function updateDetection(latest) {
    const prediction = latest.prediction;
    const isThreat = prediction !== "NORMAL";

    document.getElementById("classification").textContent =
        prediction;

    document.getElementById("normalProbability").textContent =
        percent(latest.normal_probability);

    document.getElementById("ddosProbabilityDetail").textContent =
        percent(latest.ddos_probability);

    document.getElementById("normalBar").style.width =
        `${Number(latest.normal_probability || 0) * 100}%`;

    document.getElementById("ddosBar").style.width =
        `${Number(latest.ddos_probability || 0) * 100}%`;

    document.getElementById("securityActionDetail").textContent =
        latest.security_action;

    const severity = document.getElementById("severity");

    severity.textContent = latest.severity;
    severity.classList.toggle(
        "severity-normal",
        latest.severity === "NORMAL"
    );
    severity.classList.toggle(
        "severity-high",
        latest.severity === "HIGH"
    );

    document.getElementById("mitigationActionDetail").textContent =
        latest.mitigation_action;

    document.getElementById("mitigationReason").textContent =
        latest.mitigation_reason || "No reason provided";

    setThreatState(isThreat);
}



function updateIAM(identityContext) {
    const context = identityContext || {};

    const observedSources =
        Number(context.observed_source_count || 0);

    const knownDevices =
        Number(context.known_device_count || 0);

    const unknownDevices =
        Number(context.unknown_device_count || 0);

    const deviceContexts =
        Array.isArray(context.device_contexts)
            ? context.device_contexts
            : [];

    document.getElementById("iamObservedSources").textContent =
        number(observedSources, 0);

    document.getElementById("iamKnownDevices").textContent =
        number(knownDevices, 0);

    document.getElementById("iamUnknownDevices").textContent =
        number(unknownDevices, 0);

    const identityState =
        document.getElementById("iamIdentityState");

    if (observedSources === 0) {
        identityState.textContent = "NO OBSERVED SOURCES";
        identityState.classList.remove(
            "iam-state-known",
            "iam-state-unknown"
        );
        identityState.classList.add("iam-state-empty");
    } else if (unknownDevices > 0) {
        identityState.textContent = "PARTIAL / UNKNOWN";
        identityState.classList.remove(
            "iam-state-known",
            "iam-state-empty"
        );
        identityState.classList.add("iam-state-unknown");
    } else {
        identityState.textContent = "RESOLVED";
        identityState.classList.remove(
            "iam-state-unknown",
            "iam-state-empty"
        );
        identityState.classList.add("iam-state-known");
    }

    const deviceList =
        document.getElementById("iamDeviceList");

    if (!deviceContexts.length) {
        deviceList.innerHTML = `
            <div class="iam-empty-state">
                No observed device identity context for the latest window.
            </div>
        `;
        return;
    }

    deviceList.innerHTML = deviceContexts.map(device => {
        const suspicious = device.suspicious === true;
        const denied =
            device.authorization_decision === "DENIED";

        const stateClass =
            suspicious || denied
                ? "iam-device-threat"
                : device.identity_status === "KNOWN"
                    ? "iam-device-known"
                    : "iam-device-unknown";

        const identitySource =
            device.identity_source || "LOCAL_REGISTRY";

        const environment =
            device.environment || "LIVE_CONTEXT";

        return `
            <div class="iam-device-card ${stateClass}">
                <div class="iam-device-main">
                    <strong>${device.device_id || "unknown-device"}</strong>
                    <span>${device.ip_address || "NO IP"}</span>
                </div>

                <div class="iam-device-meta">
                    <span>
                        ROLE:
                        ${device.device_role || "UNKNOWN"}
                    </span>
                    <span>
                        IDENTITY:
                        ${device.identity_status || "UNKNOWN"}
                    </span>
                    <span>
                        AUTH:
                        ${device.authentication_status || "NOT_VERIFIED"}
                    </span>
                    <span>
                        AUTHZ:
                        ${device.authorization_decision || "UNKNOWN"}
                    </span>
                </div>

                <div class="iam-device-source">
                    SOURCE: ${identitySource}
                    · ENV: ${environment}
                </div>
            </div>
        `;
    }).join("");
}


function updateTopology(topologyContext) {
    const statusEl = document.getElementById("topologyStatus");
    const environmentEl = document.getElementById("topologyEnvironment");
    const deviceCountEl = document.getElementById("topologyDeviceCount");
    const linkCountEl = document.getElementById("topologyLinkCount");
    const sensorsEl = document.getElementById("topologySensors");
    const gatewayEl = document.getElementById("topologyGateway");
    const serverEl = document.getElementById("topologyServer");
    const attackEl = document.getElementById("topologyAttackNode");
    const linkSummaryEl = document.getElementById("topologyLinkSummary");

    if (!topologyContext || typeof topologyContext !== "object") {
        if (statusEl) statusEl.textContent = "UNAVAILABLE";
        if (environmentEl) environmentEl.textContent = "UNAVAILABLE";
        if (deviceCountEl) deviceCountEl.textContent = "—";
        if (linkCountEl) linkCountEl.textContent = "—";

        if (sensorsEl) {
            sensorsEl.innerHTML =
                '<div class="topology-empty">Topology context unavailable</div>';
        }

        if (linkSummaryEl) {
            linkSummaryEl.textContent =
                "Topology relationships unavailable.";
        }

        return;
    }

    const devices = Array.isArray(topologyContext.devices)
        ? topologyContext.devices
        : [];

    const sensors = Array.isArray(topologyContext.sensors)
        ? topologyContext.sensors
        : [];

    const attackNodes =
        Array.isArray(topologyContext.controlled_attack_nodes)
            ? topologyContext.controlled_attack_nodes
            : [];

    const otServers = Array.isArray(topologyContext.ot_servers)
        ? topologyContext.ot_servers
        : [];

    const links = Array.isArray(topologyContext.links)
        ? topologyContext.links
        : [];

    if (statusEl) {
        statusEl.textContent =
            String(topologyContext.status || "UNKNOWN").toUpperCase();
    }

    if (environmentEl) {
        environmentEl.textContent =
            String(
                topologyContext.environment || "UNKNOWN"
            ).replaceAll("_", " ");
    }

    if (deviceCountEl) {
        deviceCountEl.textContent = String(devices.length);
    }

    if (linkCountEl) {
        linkCountEl.textContent = String(links.length);
    }

    function deviceName(device) {
        return (
            device.name ||
            device.device_name ||
            device.id ||
            "Unknown device"
        );
    }

    function deviceIp(device) {
        return (
            device.ip ||
            device.ip_address ||
            device.address ||
            "—"
        );
    }

    function deviceRole(device) {
        return String(
            device.role ||
            device.device_role ||
            "DEVICE"
        ).replaceAll("_", " ");
    }

    function renderChildren(device) {
        const role = document.createElement("div");
        role.className = "topology-node-role";
        role.textContent = deviceRole(device);

        const name = document.createElement("div");
        name.className = "topology-node-name";
        name.textContent = deviceName(device);

        const ip = document.createElement("div");
        ip.className = "topology-node-ip";
        ip.textContent = deviceIp(device);

        const children = [role, name, ip];

        if (
            device.authorization === "DENIED" ||
            device.simulation_only === true
        ) {
            const warning = document.createElement("div");
            warning.className = "topology-node-warning";
            warning.textContent =
                "SIMULATION ONLY • CONTROLLED NODE";
            children.push(warning);
        }

        return children;
    }

    // Sensors
    if (sensorsEl) {
        sensorsEl.replaceChildren();

        if (sensors.length === 0) {
            const empty = document.createElement("div");
            empty.className = "topology-empty";
            empty.textContent = "No declared sensors";
            sensorsEl.appendChild(empty);
        } else {
            sensors.forEach((sensor) => {
                const card = document.createElement("div");
                card.className =
                    "topology-node topology-sensor-node";

                card.replaceChildren(
                    ...renderChildren(sensor)
                );

                sensorsEl.appendChild(card);
            });
        }
    }

    // Gateway
    const gateway = topologyContext.gateway;

    if (gatewayEl && gateway) {
        gatewayEl.replaceChildren(
            ...renderChildren(gateway)
        );
    }

    // OT Server
    const server = otServers.length > 0
        ? otServers[0]
        : null;

    if (serverEl && server) {
        serverEl.replaceChildren(
            ...renderChildren(server)
        );
    }

    // Controlled attack node
    const attackNode = attackNodes.length > 0
        ? attackNodes[0]
        : null;

    if (attackEl && attackNode) {
        attackEl.replaceChildren(
            ...renderChildren(attackNode)
        );
    }

    // Declared relationships
    if (linkSummaryEl) {
        if (links.length === 0) {
            linkSummaryEl.textContent =
                "No declared topology relationships.";
        } else {
            const relationships = links.map((link) => {
                const source =
                    link.source ||
                    link.source_ip ||
                    link.from ||
                    "UNKNOWN";

                const target =
                    link.target ||
                    link.destination ||
                    link.destination_ip ||
                    link.to ||
                    "UNKNOWN";

                return `${source} → ${target}`;
            });

            linkSummaryEl.textContent =
                `DECLARED LINKS (${links.length}): ` +
                relationships.join("  •  ");
        }
    }
}



function renderObservedEvidence(items) {
    const target = document.getElementById(
        "explainObservedEvidence"
    );

    if (!target) {
        return;
    }

    if (!Array.isArray(items) || items.length === 0) {
        target.textContent =
            "No observed evidence available.";
        return;
    }

    target.innerHTML = items.map((item) => {
        const row = document.createElement("div");
        row.className = "explainability-evidence-item";
        row.textContent = item;
        return row.outerHTML;
    }).join("");
}

function updateExplainability(explainabilityContext) {
    const ctx = explainabilityContext || {};

    const status = document.getElementById("explainabilityStatus");
    const banner = document.getElementById("explainabilityStatusBanner");

    const setText = (id, value) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent =
                value === undefined || value === null || value === ""
                    ? "—"
                    : value;
        }
    };

    if (!status) {
        return;
    }

    if (!ctx || Object.keys(ctx).length === 0) {
        status.textContent = "UNAVAILABLE";
        if (banner) {
            banner.classList.remove("explainability-observed");
            banner.classList.add("explainability-unavailable");
        }
        return;
    }

    const evidenceStatus = ctx.evidence_status || "UNKNOWN";

    status.textContent = evidenceStatus;

    if (banner) {
        banner.classList.remove(
            "explainability-observed",
            "explainability-unavailable"
        );

        if (evidenceStatus === "OBSERVED") {
            banner.classList.add("explainability-observed");
        } else {
            banner.classList.add("explainability-unavailable");
        }
    }

    setText("explainPrediction", ctx.prediction);
    setText(
        "explainDdosProbability",
        typeof ctx.ddos_probability === "number"
            ? `${(ctx.ddos_probability * 100).toFixed(1)}%`
            : ctx.ddos_probability
    );
    setText(
        "explainNormalProbability",
        typeof ctx.normal_probability === "number"
            ? `${(ctx.normal_probability * 100).toFixed(1)}%`
            : ctx.normal_probability
    );

    setText("explainPacketCount", ctx.packet_count);
    setText(
        "explainPps",
        typeof ctx.packets_per_second === "number"
            ? ctx.packets_per_second.toFixed(2)
            : ctx.packets_per_second
    );
    setText(
        "explainBps",
        typeof ctx.bytes_per_second === "number"
            ? ctx.bytes_per_second.toFixed(2)
            : ctx.bytes_per_second
    );
    setText(
        "explainAvgPacketSize",
        typeof ctx.average_packet_size === "number"
            ? ctx.average_packet_size.toFixed(2)
            : ctx.average_packet_size
    );

    setText("explainSources", ctx.unique_sources);
    setText("explainDestinations", ctx.unique_destinations);
    setText("explainUdp", ctx.udp_count);
    setText("explainTcp", ctx.tcp_count);
    setText("explainIcmp", ctx.icmp_count);
    setText("explainFlows", ctx.flow_count);

    setText("explainSecurityAction", ctx.security_action);
    setText("explainSeverity", ctx.severity);
    setText("explainMitigation", ctx.mitigation_action);
    setText("explainMitigationReason", ctx.mitigation_reason);

    renderObservedEvidence(
        explainabilityContext.observed_evidence
    );
}

function updateNormalVsAttack(context) {
    const statusEl =
        document.getElementById("comparisonStatus");
    const environmentEl =
        document.getElementById("comparisonEnvironment");
    const totalEl =
        document.getElementById("comparisonTotalWindows");
    const normalEl =
        document.getElementById("comparisonNormalWindows");
    const attackEl =
        document.getElementById("comparisonAttackWindows");
    const labelEl =
        document.getElementById("comparisonAttackLabel");
    const scenarioGrid =
        document.getElementById("comparisonScenarioGrid");
    const featureList =
        document.getElementById("comparisonFeatureList");
    const banner =
        document.getElementById("comparisonStatusBanner");

    if (!context || typeof context !== "object") {
        statusEl.textContent = "UNAVAILABLE";
        environmentEl.textContent = "—";
        totalEl.textContent = "—";
        normalEl.textContent = "—";
        attackEl.textContent = "—";
        labelEl.textContent = "—";

        scenarioGrid.innerHTML =
            '<div class="comparison-empty">' +
            "Comparison context unavailable." +
            "</div>";

        featureList.innerHTML =
            '<div class="comparison-empty">' +
            "Feature contract unavailable." +
            "</div>";

        banner.classList.remove("comparison-valid");
        banner.classList.add("comparison-unavailable");
        return;
    }

    const status =
        String(context.status || "UNKNOWN").toUpperCase();

    statusEl.textContent = status;
    environmentEl.textContent =
        context.environment || "UNKNOWN";

    totalEl.textContent =
        context.total_windows ?? "—";

    normalEl.textContent =
        context.normal_windows ?? "—";

    attackEl.textContent =
        context.controlled_attack_windows ?? "—";

    labelEl.textContent =
        context.attack_label || "—";

    banner.classList.remove(
        "comparison-valid",
        "comparison-unavailable"
    );

    if (status === "CONTROLLED_VALIDATED") {
        banner.classList.add("comparison-valid");
    } else {
        banner.classList.add("comparison-unavailable");
    }

    const scenarios = Array.isArray(context.scenarios)
        ? context.scenarios
        : [];

    if (!scenarios.length) {
        scenarioGrid.innerHTML =
            '<div class="comparison-empty">' +
            "No validated scenarios available." +
            "</div>";
    } else {
        scenarioGrid.innerHTML = scenarios.map((scenario) => {
            const scenarioName =
                scenario.scenario || "UNKNOWN";

            const total =
                scenario.total_windows ?? "—";

            const normal =
                scenario.normal_windows ?? "—";

            const attack =
                scenario.attack_windows ?? "—";

            return `
                <div class="comparison-scenario-card">
                    <div class="comparison-scenario-name">
                        ${scenarioName}
                    </div>

                    <div class="comparison-scenario-status">
                        ${scenario.status || "UNKNOWN"}
                    </div>

                    <div class="comparison-scenario-values">
                        <div>
                            <span>Total</span>
                            <strong>${total}</strong>
                        </div>

                        <div>
                            <span>Normal</span>
                            <strong>${normal}</strong>
                        </div>

                        <div>
                            <span>Attack</span>
                            <strong>${attack}</strong>
                        </div>
                    </div>
                </div>
            `;
        }).join("");
    }

    const features = Array.isArray(context.features)
        ? context.features
        : [];

    if (!features.length) {
        featureList.innerHTML =
            '<div class="comparison-empty">' +
            "No feature contract available." +
            "</div>";
    } else {
        featureList.innerHTML = features.map((feature) => `
            <div class="comparison-feature-chip">
                ${feature}
            </div>
        `).join("");
    }
}

function updateLifecycle(lifecycleContext) {
    const state = document.getElementById("lifecycleState");
    const stage = document.getElementById("lifecycleStage");
    const implementation =
        document.getElementById("lifecycleImplementation");
    const enforcement =
        document.getElementById("lifecycleEnforcement");
    const recovery =
        document.getElementById("lifecycleRecovery");
    const windowStart =
        document.getElementById("lifecycleWindowStart");
    const banner =
        document.getElementById("lifecycleStatusBanner");

    if (!lifecycleContext || lifecycleContext.available !== true) {
        state.textContent = "UNAVAILABLE";
        stage.textContent = "—";
        implementation.textContent = "—";
        enforcement.textContent = "—";
        recovery.textContent = "—";
        windowStart.textContent = "—";

        banner.classList.remove(
            "lifecycle-normal",
            "lifecycle-alert",
            "lifecycle-response",
            "lifecycle-unavailable"
        );

        banner.classList.add("lifecycle-unavailable");

        return;
    }

    const lifecycleState =
        lifecycleContext.lifecycle_state || "UNAVAILABLE";

    const lifecycleStage =
        lifecycleContext.lifecycle_stage || "—";

    state.textContent = lifecycleState;
    stage.textContent = lifecycleStage;
    implementation.textContent =
        lifecycleContext.implementation_status || "—";
    enforcement.textContent =
        lifecycleContext.enforcement_status || "—";
    recovery.textContent =
        lifecycleContext.recovery_status || "—";
    windowStart.textContent =
        lifecycleContext.window_start || "—";

    banner.classList.remove(
        "lifecycle-normal",
        "lifecycle-alert",
        "lifecycle-response",
        "lifecycle-unavailable"
    );

    if (lifecycleState === "NORMAL") {
        banner.classList.add("lifecycle-normal");
    } else if (
        lifecycleState === "ALERTED" ||
        lifecycleState === "DETECTED"
    ) {
        banner.classList.add("lifecycle-alert");
    } else if (
        lifecycleState === "MITIGATION_RECOMMENDED"
    ) {
        banner.classList.add("lifecycle-response");
    } else {
        banner.classList.add("lifecycle-unavailable");
    }
}

function updatePipeline(pipeline) {
    const states = [
        ["pipelineTraffic", pipeline.traffic_features],
        ["pipelineFeatures", pipeline.traffic_features],
        ["pipelineML", pipeline.ml_predictions],
        ["pipelineSecurity", pipeline.security_decisions],
        ["pipelineMitigation", pipeline.mitigation_decisions]
    ];

    for (const [id, active] of states) {
        const element = document.getElementById(id);

        element.textContent = active ? "ONLINE" : "OFFLINE";

        element.style.color = active
            ? "var(--green)"
            : "var(--red)";
    }
}


function createCharts(rows) {
    const labels = rows.map(row => row.window_start);
    const traffic = rows.map(row => row.packets_per_second);
    const threat = rows.map(row => row.ddos_probability * 100);

    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
            legend: {
                display: false
            }
        },
        scales: {
            x: {
                ticks: {
                    color: "#7890a8",
                    maxTicksLimit: 6
                },
                grid: {
                    color: "rgba(27,49,75,0.45)"
                }
            },
            y: {
                beginAtZero: true,
                ticks: {
                    color: "#7890a8"
                },
                grid: {
                    color: "rgba(27,49,75,0.45)"
                }
            }
        }
    };


    if (trafficChart) {
        trafficChart.destroy();
    }

    if (threatChart) {
        threatChart.destroy();
    }


    trafficChart = new Chart(
        document.getElementById("trafficChart"),
        {
            type: "line",

            data: {
                labels,

                datasets: [
                    {
                        label: "Packets/sec",
                        data: traffic,
                        borderColor: "#35d4ff",
                        backgroundColor: "rgba(53,212,255,0.08)",
                        fill: true,
                        tension: 0.25,
                        pointRadius: 2
                    }
                ]
            },

            options: commonOptions
        }
    );


    threatChart = new Chart(
        document.getElementById("threatChart"),
        {
            type: "line",

            data: {
                labels,

                datasets: [
                    {
                        label: "DDoS Probability",
                        data: threat,
                        borderColor: "#ff5577",
                        backgroundColor: "rgba(255,85,119,0.08)",
                        fill: true,
                        tension: 0.25,
                        pointRadius: 2
                    }
                ]
            },

            options: {
                ...commonOptions,

                scales: {
                    ...commonOptions.scales,

                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            color: "#7890a8",
                            callback: value => `${value}%`
                        },
                        grid: {
                            color: "rgba(27,49,75,0.45)"
                        }
                    }
                }
            }
        }
    );
}


function updateEvents(events) {
    const table = document.getElementById("eventsTable");

    document.getElementById("eventCount").textContent =
        events.length;

    if (!events.length) {
        table.innerHTML = `
            <tr>
                <td colspan="7" class="empty-state">
                    No security events detected
                </td>
            </tr>
        `;

        return;
    }


    table.innerHTML = events.map(event => {

        const threat =
            event.prediction !== "NORMAL";

        return `
            <tr>
                <td>${event.window_start}</td>
                <td>${number(event.packet_count, 0)}</td>
                <td>${number(event.packets_per_second)}</td>
                <td class="${threat ? "event-threat" : "event-normal"}">
                    ${event.prediction}
                </td>
                <td>${percent(event.ddos_probability)}</td>
                <td>${event.security_action}</td>
                <td>${event.mitigation_action}</td>
            </tr>
        `;

    }).join("");
}


function updateEnergy(energyData) {

    const statusElement =
        document.getElementById("energyTelemetryStatus");

    const windowCountElement =
        document.getElementById("energyWindowCount");

    const fields = {
        energyEstimate: document.getElementById("energyEstimate"),
        energyRate: document.getElementById("energyRate"),
        energyPerPacket: document.getElementById("energyPerPacket"),
        energyBaseline: document.getElementById("energyBaseline"),
        energyDeviation: document.getElementById("energyDeviation"),
        energyIncrease: document.getElementById("energyIncrease"),
        energyTxActivity: document.getElementById("energyTxActivity"),
        energyRxActivity: document.getElementById("energyRxActivity"),
        energyCpuActivity: document.getElementById("energyCpuActivity"),
        energyCause: document.getElementById("energyCause"),
        energyWindowStart: document.getElementById("energyWindowStart")
    };


    if (!energyData || !Array.isArray(energyData.rows)) {

        statusElement.textContent = "UNAVAILABLE";
        windowCountElement.textContent = "0";

        Object.values(fields).forEach((element) => {
            if (element) {
                element.textContent = "—";
            }
        });

        return;
    }


    const rows = energyData.rows;

    windowCountElement.textContent =
        energyData.count ?? rows.length;


    if (!rows.length) {

        statusElement.textContent = "NO DATA";

        Object.values(fields).forEach((element) => {
            if (element) {
                element.textContent = "—";
            }
        });

        return;
    }


    const latest =
        rows[rows.length - 1];


    const formatNumber = (value, digits = 2) => {

        const number = Number(value);

        if (!Number.isFinite(number)) {
            return "—";
        }

        return number.toFixed(digits);
    };


    const formatPercent = (value) => {

        const number = Number(value);

        if (!Number.isFinite(number)) {
            return "—";
        }

        return `${number.toFixed(2)}%`;
    };


    fields.energyEstimate.textContent =
        formatNumber(latest.energy_estimate);

    fields.energyRate.textContent =
        formatNumber(latest.energy_rate);

    fields.energyPerPacket.textContent =
        formatNumber(latest.energy_per_packet, 6);

    fields.energyBaseline.textContent =
        formatNumber(latest.baseline_energy);

    fields.energyDeviation.textContent =
        formatNumber(latest.energy_deviation);

    fields.energyIncrease.textContent =
        formatPercent(latest.energy_increase_percent);

    fields.energyTxActivity.textContent =
        formatNumber(latest.tx_activity);

    fields.energyRxActivity.textContent =
        formatNumber(latest.rx_activity);

    fields.energyCpuActivity.textContent =
        formatNumber(latest.cpu_activity);

    fields.energyCause.textContent =
        latest.energy_cause || "—";

    fields.energyWindowStart.textContent =
        latest.window_start || "—";


    if (
        latest.measurement_status === "MODELLED" &&
        latest.environment === "CONTROLLED_SIMULATION" &&
        latest.hardware_measured === false
    ) {
        statusElement.textContent =
            "MODELLED • CONTROLLED SIMULATION";
    } else {
        statusElement.textContent =
            "DATA AVAILABLE";
    }
}


async function refreshDashboard() {

    try {

        const statusResponse =
            await fetch("/api/status", {
                cache: "no-store"
            });

        const status =
            await statusResponse.json();


        const online =
            status.status === "ONLINE";

        const statusElement =
            document.getElementById("systemStatus");

        const dot =
            document.getElementById("statusDot");

        statusElement.textContent =
            online ? "ONLINE" : "NO DATA";

        dot.classList.toggle("online", online);
        dot.classList.toggle("offline", !online);


        updateSummary(status.summary);
        updatePipeline(status.pipeline);


        const liveResponse =
            await fetch("/api/live-data", {
                cache: "no-store"
            });

        const liveData =
            await liveResponse.json();


        if (liveData.rows.length) {

            const latest =
                liveData.rows[liveData.rows.length - 1];

            updateDetection(latest);
            updateIAM(latest.identity_context);
            updateLifecycle(latest.lifecycle_context);
            updateExplainability(latest.explainability_context);
            createCharts(liveData.rows);
        }


        const eventsResponse =
            await fetch("/api/events", {
                cache: "no-store"
            });

        const eventsData =
            await eventsResponse.json();

        updateEvents(eventsData.events);


        const energyResponse =
            await fetch("/api/energy-context", {
                cache: "no-store"
            });

        const energyData =
            await energyResponse.json();

        updateEnergy(energyData);


        const topologyResponse =
            await fetch("/api/topology-context", {
                cache: "no-store"
            });

        const topologyData =
            await topologyResponse.json();

        updateTopology(topologyData);

        const comparisonResponse =
            await fetch("/api/normal-vs-attack", {
                cache: "no-store"
            });

        const comparisonData =
            await comparisonResponse.json();

        updateNormalVsAttack(comparisonData);




    } catch (error) {

        console.error(
            "Dashboard refresh failed:",
            error
        );

        document.getElementById(
            "systemStatus"
        ).textContent = "OFFLINE";

        document.getElementById(
            "statusDot"
        ).classList.add("offline");
    }
}


refreshDashboard();

setInterval(
    refreshDashboard,
    5000
);

/* ============================================================
   CONTROLLED SECURITY DEMONSTRATION
   ============================================================ */

async function runControlledDemo() {

    const button = document.getElementById("run-demo-btn");
    const results = document.getElementById("demo-results");

    if (!button || !results) {
        return;
    }

    button.disabled = true;
    button.textContent = "RUNNING DEMO...";

    results.innerHTML = `
        <div class="demo-placeholder">
            <span>DEMO STATUS</span>
            <strong>PROCESSING</strong>
            <small>Running validated decision path...</small>
        </div>
    `;

    try {

        const response = await fetch("/api/demo-data", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const demo = await response.json();

        results.innerHTML = `
            <div class="demo-result-grid">

                <div class="demo-result-item">
                    <span>PREDICTION</span>
                    <strong class="demo-threat">
                        ${demo.prediction}
                    </strong>
                </div>

                <div class="demo-result-item">
                    <span>DDoS PROBABILITY</span>
                    <strong>
                        ${(demo.ddos_probability * 100).toFixed(0)}%
                    </strong>
                </div>

                <div class="demo-result-item">
                    <span>SECURITY ACTION</span>
                    <strong class="demo-threat">
                        ${demo.security_action}
                    </strong>
                </div>

                <div class="demo-result-item">
                    <span>SEVERITY</span>
                    <strong class="demo-threat">
                        ${demo.severity}
                    </strong>
                </div>

                <div class="demo-result-item demo-result-wide">
                    <span>MITIGATION DECISION</span>
                    <strong class="demo-threat">
                        ${demo.mitigation_action}
                    </strong>
                </div>

            </div>

            <div class="demo-verification">
                <span>✓ CONTROLLED</span>
                <span>✓ OFFLINE ONLY</span>
                <span>
                    ✓ ENFORCEMENT:
                    ${demo.enforcement ? "ACTIVE" : "NOT IMPLEMENTED"}
                </span>
            </div>
        `;

    } catch (error) {

        console.error("Controlled demo failed:", error);

        results.innerHTML = `
            <div class="demo-placeholder demo-error">
                <span>DEMO STATUS</span>
                <strong>ERROR</strong>
                <small>${error.message}</small>
            </div>
        `;

    } finally {

        button.disabled = false;
        button.textContent = "RUN CONTROLLED DEMO";

    }
}


const controlledDemoButton =
    document.getElementById("run-demo-btn");

if (controlledDemoButton) {
    controlledDemoButton.addEventListener(
        "click",
        runControlledDemo
    );
}

