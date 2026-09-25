// =========================================================
//  AI SHIELD — Phishing & Threat Detection Engine
//  Frontend Logic v2.0
// =========================================================

/* ============================= */
/* HELPERS                       */
/* ============================= */

function getThreatLevel(score) {
    if (score < 25) return { level: 'safe', label: 'SAFE', class: 'verdict-safe', color: '#22c55e' };
    if (score < 50) return { level: 'warning', label: 'SUSPICIOUS', class: 'verdict-warning', color: '#f59e0b' };
    return { level: 'danger', label: 'PHISHING', class: 'verdict-phishing', color: '#ef4444' };
}

function createInfoRow(label, value) {
    return `
        <div class="info-row">
            <span class="label">${label}</span>
            <span class="value">${value}</span>
        </div>
    `;
}

/* ============================= */
/* DASHBOARD CARDS               */
/* ============================= */

function createSSLCard(ssl) {
    const status = ssl.ssl_available
        ? '<span class="text-safe"><i class="fa-solid fa-lock"></i> Valid</span>'
        : '<span class="text-danger"><i class="fa-solid fa-lock-open"></i> Invalid</span>';

    return `
        <div class="dashboard-card">
            <h3><i class="fa-solid fa-lock"></i> SSL Certificate</h3>
            ${createInfoRow("Status", status)}
            ${createInfoRow("Issuer", ssl.issuer || "N/A")}
            ${createInfoRow("Days Left", ssl.days_remaining ?? "N/A")}
            ${createInfoRow("Expiry", ssl.expiry_date || "N/A")}
        </div>
    `;
}

function createDNSCard(dns) {
    return `
        <div class="dashboard-card">
            <h3><i class="fa-solid fa-globe"></i> DNS Information</h3>
            ${createInfoRow("MX Records", dns["MX Records"]?.length ?? 0)}
            ${createInfoRow("A Records", dns["A Records"]?.length ?? 0)}
            ${createInfoRow("NS Records", dns["NS Records"]?.length ?? 0)}
        </div>
    `;
}

function createWhoisCard(whois) {
    const years = whois.domain_age_days ? Math.floor(whois.domain_age_days / 365) : "N/A";
    const expiry = whois.days_until_expiry ? whois.days_until_expiry + " Days" : "N/A";

    return `
        <div class="dashboard-card">
            <h3><i class="fa-solid fa-fingerprint"></i> WHOIS Information</h3>
            ${createInfoRow("Domain Age", years + " Years")}
            ${createInfoRow("Country", whois.country || "N/A")}
            ${createInfoRow("Registrar", whois.registrar || "N/A")}
            ${createInfoRow("Expiry", expiry)}
        </div>
    `;
}

function createKeywordCard(keyword) {
    const keywords = keyword.matched_keywords?.length > 0
        ? keyword.matched_keywords.join(", ")
        : '<span class="text-safe">None detected</span>';

    return `
        <div class="dashboard-card">
            <h3><i class="fa-solid fa-triangle-exclamation"></i> Keyword Analysis</h3>
            ${createInfoRow("Matches", keyword.total_matches ?? 0)}
            ${createInfoRow("Keywords", keywords)}
        </div>
    `;
}

/* ============================= */
/* WARNINGS & RECOMMENDATIONS    */
/* ============================= */

function createWarnings(warnings) {
    if (!warnings || warnings.length === 0) {
        return `
            <div class="warning-card">
                <h3><i class="fa-solid fa-shield-halved"></i> Threat Warnings</h3>
                <p class="text-safe"><i class="fa-solid fa-check-circle"></i> No security warnings detected.</p>
            </div>
        `;
    }

    return `
        <div class="warning-card">
            <h3><i class="fa-solid fa-triangle-exclamation"></i> Threat Warnings</h3>
            <ul>
                ${warnings.map(w => `<li>${w}</li>`).join("")}
            </ul>
        </div>
    `;
}

function createRecommendations(recommendations) {
    if (!recommendations || recommendations.length === 0) {
        return `
            <div class="recommend-card">
                <h3><i class="fa-solid fa-user-shield"></i> Recommendations</h3>
                <p class="text-safe"><i class="fa-solid fa-check-circle"></i> Safe to browse — no action required.</p>
            </div>
        `;
    }

    return `
        <div class="recommend-card">
            <h3><i class="fa-solid fa-user-shield"></i> Security Recommendations</h3>
            <ul>
                ${recommendations.map(r => `<li>${r}</li>`).join("")}
            </ul>
        </div>
    `;
}

/* ============================= */
/* HISTORY                       */
/* ============================= */

function saveHistory(data, type = "url") {

    let history = JSON.parse(localStorage.getItem("scanHistory")) || [];

    let historyItem;

    if (type === "email") {

        const threatScore =
            data.threat_analysis?.overall_score ?? 0;

        const verdict =
            data.threat_analysis?.verdict || "UNKNOWN";

        const subject =
            data.email?.subject || "No Subject";

        const sender =
            data.email?.sender || "Unknown Sender";

        historyItem = {
            type: "email",
            subject: subject,
            sender: sender,
            prediction: verdict,
            score: threatScore,
            date: new Date().toLocaleString()
        };

    } else {

        historyItem = {
            type: "url",
            url: data.url,
            prediction:
                data.machine_learning?.prediction || "UNKNOWN",
            score:
                data.threat_analysis?.overall_score ?? 0,
            date: new Date().toLocaleString()
        };
    }

    history.unshift(historyItem);

    // Keep last 20 scans
    history = history.slice(0, 20);

    localStorage.setItem(
        "scanHistory",
        JSON.stringify(history)
    );
}

function loadHistory() {

    const history =
        JSON.parse(localStorage.getItem("scanHistory")) || [];

    const list =
        document.getElementById("historyList");

    if (!list) return;

    if (history.length === 0) {

        list.innerHTML = `
            <p class="empty-history">
                <i class="fa-regular fa-folder-open"></i>
                No scans recorded yet.
            </p>
        `;

        return;
    }

    list.innerHTML = "";

    history.forEach((item, index) => {

        const isEmail = item.type === "email";

        const score = item.score ?? 0;

        const threatInfo = getThreatLevel(score);

        const isPhishing =
            item.prediction === "PHISHING" ||
            item.prediction === "LIKELY PHISHING";

        /* =========================
           EMAIL HISTORY ITEM
           ========================= */

        if (isEmail) {

            list.innerHTML += `
                <div class="history-item email-history-item"
                     onclick="reloadEmail(${index})">

                    <div>

                        <div class="history-url">
                            <i class="fa-solid fa-envelope"></i>
                            ${item.subject || "No Subject"}
                        </div>

                        <div class="history-time">
                            <i class="fa-solid fa-user"></i>
                            ${item.sender || "Unknown Sender"}
                        </div>

                        <div class="history-time">
                            <i class="fa-regular fa-clock"></i>
                            ${item.date}
                        </div>

                    </div>

                    <div class="history-meta">

                        <span class="history-status ${
                            isPhishing
                                ? 'status-phishing'
                                : 'status-safe'
                        }">
                            ${item.prediction}
                        </span>

                        <span class="font-mono text-muted"
                              style="font-size: 13px;">
                            ${score}/100
                        </span>

                    </div>

                </div>
            `;

        }

        /* =========================
           URL HISTORY ITEM
           ========================= */

        else {

            list.innerHTML += `
                <div class="history-item"
                     onclick="reloadURL('${item.url}')">

                    <div>

                        <div class="history-url">
                            <i class="fa-solid fa-link"></i>
                            ${item.url}
                        </div>

                        <div class="history-time">
                            <i class="fa-regular fa-clock"></i>
                            ${item.date}
                        </div>

                    </div>

                    <div class="history-meta">

                        <span class="history-status ${
                            isPhishing
                                ? 'status-phishing'
                                : 'status-safe'
                        }">
                            ${item.prediction}
                        </span>

                        <span class="font-mono text-muted"
                              style="font-size: 13px;">
                            ${score}/100
                        </span>

                    </div>

                </div>
            `;
        }
    });
}

function reloadURL(url) {
    document.getElementById("urlInput").value = url;
    showPage('dashboard');
    setTimeout(() => analyzeURL(), 100);
}

function reloadEmail(index) {

    const history =
        JSON.parse(localStorage.getItem("scanHistory")) || [];

    const item = history[index];

    if (!item || item.type !== "email") {
        return;
    }

    // Open Email Scanner
    showPage("email");

    // Pre-fill the sender and subject fields with
    // the stored summary values.
    const emailFrom = document.getElementById("emailFrom");
    const emailSubject = document.getElementById("emailSubject");
    const emailInput = document.getElementById("emailInput");

    if (emailFrom) {
        emailFrom.value = item.sender || "";
    }

    if (emailSubject) {
        emailSubject.value = item.subject || "";
    }

    // We only stored summary information,
    // not the complete raw email.
    if (emailInput) {

        emailInput.value =
            `This email scan was previously recorded in Scan History.

Threat Verdict: ${item.prediction}
Threat Score: ${item.score}/100

Note: Original email content was not stored for security/privacy reasons.`;
    }
}

function clearHistory() {
    if (!confirm("Are you sure you want to clear all scan history?")) return;
    localStorage.removeItem("scanHistory");
    loadHistory();
}

/* ============================= */
/* MAIN ANALYSIS                 */
/* ============================= */

async function analyzeURL() {
    const urlInput = document.getElementById("urlInput");
    const url = urlInput.value.trim();

    if (!url) {
        alert("Please enter a URL to analyze.");
        return;
    }

    const loading = document.getElementById("loading");
    const result = document.getElementById("result");

    loading.classList.add("active");
    result.innerHTML = "";
    urlInput.classList.remove("threat-detected");

    try {
        const response = await fetch("https://ai-phishing-detection-system-9c4u.onrender.com/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        loading.classList.remove("active");

        if (data.status === "FAILED") {
            alert(data.message || "Analysis failed.");
            return;
        }

        // ----- Active report switching: website scan wins -----
        // Email scan is no longer the active report
        window.latestEmailScan = null;
        localStorage.removeItem("latestEmailScan");

        // Make this the active website report
        window.latestScan = data;
        localStorage.setItem(
            "latestScan",
            JSON.stringify(data)
        );

        // Save and refresh history
        saveHistory(data);
        loadHistory();

        const prediction = data.machine_learning?.prediction || "UNKNOWN";
        const confidence = data.machine_learning?.confidence ?? 0;
        const threat = data.threat_analysis?.overall_score ?? 0;
        const verdict = data.threat_analysis?.verdict || "Unknown";
        const threatInfo = getThreatLevel(threat);

        // Add threat styling to input
        if (threat >= 50) {
            urlInput.classList.add("threat-detected");
        }

        // Gauge circumference
        const radius = 85;
        const circumference = 2 * Math.PI * radius;

        // Determine progress bar class
        const progressClass = threat >= 75 ? 'progress-danger' : (threat >= 25 ? 'progress-warning' : '');

        // Build result HTML
        result.innerHTML = `
            <!-- Verdict Summary -->
            <div class="summary-card ${threatInfo.class}">
                <div class="summary-layout">
                    <div class="summary-left">
                        <h2 style="color: ${threatInfo.color};">
                            <i class="fa-solid ${threat >= 50 ? 'fa-triangle-exclamation' : 'fa-shield-halved'}"></i>
                            ${prediction}
                        </h2>
                        <p><span class="label">Confidence:</span> <span class="value">${confidence}%</span></p>
                        <div class="progress ${progressClass}">
                            <div class="progress-fill" style="width: ${confidence}%"></div>
                        </div>
                        <p>
                            <span class="label">Verdict:</span>
                            <span class="value" style="color: ${threatInfo.color};">${verdict}</span>
                        </p>
                        <p>
                            <span class="label">Threat Score:</span>
                            <span class="value font-mono" style="color: ${threatInfo.color};">${threat}/100</span>
                        </p>
                    </div>

                    <div class="summary-right">
                        <div class="gauge">
                            <svg width="220" height="220">
                                <circle class="gauge-bg" cx="110" cy="110" r="85"></circle>
                                <circle id="gauge-progress" class="gauge-progress ${threatInfo.level === 'warning' ? 'warning' : ''} ${threatInfo.level === 'danger' ? 'danger' : ''}" cx="110" cy="110" r="85"></circle>
                            </svg>
                            <div class="gauge-text">
                                <h1 id="score-number">0</h1>
                                <span>/100</span>
                            </div>
                        </div>
                        <h3>Threat Level</h3>
                        <p style="color: ${threatInfo.color};">${threatInfo.label}</p>
                    </div>
                </div>
            </div>

            <!-- Analysis Grid -->
            <div class="dashboard-grid">
                ${createSSLCard(data.ssl?.data || {})}
                ${createDNSCard(data.dns?.data || {})}
                ${createWhoisCard(data.whois || {})}
                ${createKeywordCard(data.keywords?.data || {})}
            </div>

            <!-- Warnings & Recommendations -->
            ${createWarnings(data.threat_analysis?.warnings)}
            ${createRecommendations(data.threat_analysis?.recommendations)}
        `;

        // Animate Gauge
        const circle = document.getElementById("gauge-progress");
        const scoreElement = document.getElementById("score-number");

        circle.style.strokeDasharray = circumference;
        circle.style.strokeDashoffset = circumference;

        // Animate number
        let current = 0;
        const timer = setInterval(() => {
            if (current >= threat) {
                clearInterval(timer);
                scoreElement.textContent = threat;
            } else {
                current++;
                scoreElement.textContent = current;
            }
        }, 15);

        // Animate gauge fill
        const offset = circumference - (threat / 100) * circumference;
        setTimeout(() => {
            circle.style.strokeDashoffset = offset;
        }, 200);

    } catch (error) {
        loading.classList.remove("active");
        console.error(error);
        alert("Connection error: " + (error.message || "Unable to reach analysis server."));
    }
}

/* ============================= */
/* EMAIL ANALYSIS                */
/* ============================= */

async function analyzeEmail() {

    const from = document.getElementById("emailFrom").value.trim();
    const subject = document.getElementById("emailSubject").value.trim();
    const body = document.getElementById("emailInput").value.trim();

    if (!from) {
        alert("Please enter the sender email.");
        return;
    }

    if (!subject) {
        alert("Please enter the email subject.");
        return;
    }

    if (!body) {
        alert("Please paste the email body.");
        return;
    }

    const loading = document.getElementById("emailLoading");
    const result = document.getElementById("emailResult");

    loading.classList.add("active");
    result.innerHTML = "";

    // Build the raw email expected by backend
    const rawEmail =
`From: ${from}
Subject: ${subject}

${body}`;

    try {

        const response = await fetch(
            "https://ai-phishing-detection-system-9c4u.onrender.com/analyze-email",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    raw_email: rawEmail
                })
            }
        );

        const data = await response.json();

        loading.classList.remove("active");

        if (data.status === "FAILED") {
            alert(data.message || "Email analysis failed.");
            return;
        }

        // ----- Active report switching: email scan wins -----
        // Website scan is no longer the active report
        window.latestScan = null;
        localStorage.removeItem("latestScan");

        // Make this the active email report
        window.latestEmailScan = data;
        localStorage.setItem(
            "latestEmailScan",
            JSON.stringify(data)
        );

        // Save to history
        saveHistory(data, "email");

        // Refresh history
        loadHistory();

        // Display result
        renderEmailResults(data);

    } catch (error) {

        loading.classList.remove("active");

        console.error(error);

        alert(
            "Connection error: " +
            (error.message || "Unable to reach analysis server.")
        );
    }
}


/* ============================= */
/* EMAIL RESULT RENDERER         */
/* ============================= */

function renderEmailResults(data) {

    const result = document.getElementById("emailResult");

    const email = data.email || {};
    const keyword = data.keyword_analysis?.data || {};
    const spam = data.spam_analysis?.data || {};
    const intent = data.intent_analysis?.data || {};
    const sender = data.sender_analysis?.data || {};
    const links = data.link_analysis?.data || {};
    const threat = data.threat_analysis?.data || {};

    const score = threat.overall_score ?? 0;
    const verdict = threat.verdict || "UNKNOWN";
    const securityLevel = threat.security_level || "UNKNOWN";

    let threatInfo;

    if (score < 25) {

        threatInfo = {
            color: "#22c55e",
            icon: "fa-shield-halved",
            className: "verdict-safe"
        };

    } else if (score < 50) {

        threatInfo = {
            color: "#f59e0b",
            icon: "fa-triangle-exclamation",
            className: "verdict-warning"
        };

    } else {

        threatInfo = {
            color: "#ef4444",
            icon: "fa-skull-crossbones",
            className: "verdict-phishing"
        };
    }


    /* ============================= */
    /* LINK RESULTS                  */
    /* ============================= */

    let linkHTML = "";

    if (!links.links || links.links.length === 0) {

        linkHTML = `
            <p class="text-safe">
                <i class="fa-solid fa-circle-check"></i>
                No links detected
            </p>
        `;

    } else {

        linkHTML = links.links.map((link, index) => {

            const website = link.website_analysis || {};
            const websiteThreat =
                website.threat_analysis?.overall_score ?? 0;

            const websiteVerdict =
                website.threat_analysis?.verdict || "UNKNOWN";

            return `
                <div class="email-link-item">

                    <div class="email-link-header">
                        <span>
                            <i class="fa-solid fa-link"></i>
                            Link ${index + 1}
                        </span>

                        <span class="font-mono">
                            ${link.score ?? 0}/100
                        </span>
                    </div>

                    <div class="email-link-url">
                        ${link.url || "Unknown URL"}
                    </div>

                    <div class="info-row">
                        <span class="label">URL Risk</span>
                        <span class="value">
                            ${link.risk_level || "UNKNOWN"}
                        </span>
                    </div>

                    <div class="info-row">
                        <span class="label">Website Threat Score</span>
                        <span class="value">
                            ${websiteThreat}/100
                        </span>
                    </div>

                    <div class="info-row">
                        <span class="label">Website Verdict</span>
                        <span class="value">
                            ${websiteVerdict}
                        </span>
                    </div>

                </div>
            `;

        }).join("");
    }


    /* ============================= */
    /* WARNINGS                     */
    /* ============================= */

    const warnings = data.warnings || [];

    const warningsHTML = warnings.length
        ? `
            <div class="warning-card">
                <h3>
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    Email Warnings
                </h3>

                <ul>
                    ${warnings.map(w => `<li>${w}</li>`).join("")}
                </ul>
            </div>
        `
        : `
            <div class="warning-card">
                <h3>
                    <i class="fa-solid fa-shield-halved"></i>
                    Email Warnings
                </h3>

                <p class="text-safe">
                    <i class="fa-solid fa-circle-check"></i>
                    No security warnings detected.
                </p>
            </div>
        `;


    /* ============================= */
    /* RECOMMENDATIONS               */
    /* ============================= */

    const recommendations = data.recommendations || [];

    const recommendationsHTML = recommendations.length
        ? `
            <div class="recommend-card">

                <h3>
                    <i class="fa-solid fa-user-shield"></i>
                    Security Recommendations
                </h3>

                <ul>
                    ${recommendations.map(r => `<li>${r}</li>`).join("")}
                </ul>

            </div>
        `
        : "";


    /* ============================= */
    /* MAIN EMAIL RESULT             */
    /* ============================= */

    result.innerHTML = `

        <!-- Email Threat Summary -->

        <div class="summary-card ${threatInfo.className}">

            <div class="summary-layout">

                <div class="summary-left">

                    <h2 style="color: ${threatInfo.color};">

                        <i class="fa-solid ${threatInfo.icon}"></i>

                        ${verdict}

                    </h2>

                    <p>
                        <span class="label">
                            Threat Score:
                        </span>

                        <span
                            class="value font-mono"
                            style="color: ${threatInfo.color};">

                            ${score}/100

                        </span>
                    </p>

                    <p>
                        <span class="label">
                            Security Level:
                        </span>

                        <span class="value">
                            ${securityLevel}
                        </span>
                    </p>

                    <p>
                        <span class="label">
                            Intent:
                        </span>

                        <span class="value">
                            ${intent.category || "UNKNOWN"}
                        </span>
                    </p>

                    <p>
                        <span class="label">
                            Spam:
                        </span>

                        <span class="value">
                            ${spam.verdict || "UNKNOWN"}
                        </span>
                    </p>

                </div>

                <div class="summary-right">

                    <div class="gauge">

                        <svg width="220" height="220">

                            <circle
                                class="gauge-bg"
                                cx="110"
                                cy="110"
                                r="85">
                            </circle>

                            <circle
                                id="email-gauge-progress"
                                class="gauge-progress
                                ${score >= 25 && score < 50 ? "warning" : ""}
                                ${score >= 50 ? "danger" : ""}"
                                cx="110"
                                cy="110"
                                r="85">
                            </circle>

                        </svg>

                        <div class="gauge-text">

                            <h1 id="email-score-number">
                                0
                            </h1>

                            <span>/100</span>

                        </div>

                    </div>

                    <h3>Email Threat Level</h3>

                    <p style="color: ${threatInfo.color};">
                        ${securityLevel}
                    </p>

                </div>

            </div>

        </div>


        <!-- Email Information -->

        <div class="dashboard-grid">

            <div class="dashboard-card">

                <h3>
                    <i class="fa-solid fa-envelope"></i>
                    Email Information
                </h3>

                ${createInfoRow(
                    "Sender",
                    email.sender || "N/A"
                )}

                ${createInfoRow(
                    "Recipient",
                    email.recipient || "N/A"
                )}

                ${createInfoRow(
                    "Subject",
                    email.subject || "N/A"
                )}

                ${createInfoRow(
                    "Links",
                    email.link_count ?? 0
                )}

                ${createInfoRow(
                    "Attachments",
                    email.attachments?.length ?? 0
                )}

                ${createInfoRow(
                    "HTML Email",
                    email.is_html ? "Yes" : "No"
                )}

            </div>


            <div class="dashboard-card">

                <h3>
                    <i class="fa-solid fa-user-secret"></i>
                    Sender Analysis
                </h3>

                ${createInfoRow(
                    "Sender Score",
                    `${sender.sender_score ?? 0}/100`
                )}

                ${createInfoRow(
                    "Risk Level",
                    sender.risk_level || "UNKNOWN"
                )}

                ${createInfoRow(
                    "Domain",
                    sender.domain || "N/A"
                )}

                ${createInfoRow(
                    "Free Provider",
                    sender.free_email_provider ? "Yes" : "No"
                )}

                ${createInfoRow(
                    "IP Sender",
                    sender.ip_address_sender ? "Yes" : "No"
                )}

            </div>


            <div class="dashboard-card">

                <h3>
                    <i class="fa-solid fa-bullseye"></i>
                    Intent Analysis
                </h3>

                ${createInfoRow(
                    "Category",
                    intent.category || "UNKNOWN"
                )}

                ${createInfoRow(
                    "Confidence",
                    `${intent.confidence ?? 0}%`
                )}

            </div>


            <div class="dashboard-card">

                <h3>
                    <i class="fa-solid fa-ban"></i>
                    Spam Analysis
                </h3>

                ${createInfoRow(
                    "Verdict",
                    spam.verdict || "UNKNOWN"
                )}

                ${createInfoRow(
                    "Spam Score",
                    spam.spam_score ?? 0
                )}

                ${createInfoRow(
                    "Spam Level",
                    spam.spam_level || "UNKNOWN"
                )}

            </div>


            <div class="dashboard-card">

                <h3>
                    <i class="fa-solid fa-key"></i>
                    Phishing Keywords
                </h3>

                ${createInfoRow(
                    "Detected",
                    keyword.phishing_count ?? 0
                )}

                ${createInfoRow(
                    "Keywords",
                    keyword.phishing_keywords?.length
                        ? keyword.phishing_keywords.join(", ")
                        : "None detected"
                )}

            </div>


            <div class="dashboard-card">

                <h3>
                    <i class="fa-solid fa-link"></i>
                    Email Links
                </h3>

                ${createInfoRow(
                    "Link Count",
                    links.link_count ?? 0
                )}

                ${createInfoRow(
                    "Highest Risk",
                    `${links.highest_risk_score ?? 0}/100`
                )}

                ${createInfoRow(
                    "Risk Level",
                    links.highest_risk_level || "UNKNOWN"
                )}

            </div>

        </div>


        <!-- Detailed Links -->

        <div class="dashboard-card email-links-card">

            <h3>
                <i class="fa-solid fa-link"></i>
                Link Analysis
            </h3>

            ${linkHTML}

        </div>


        <!-- Threat Breakdown -->

        <div class="dashboard-card">

            <h3>
                <i class="fa-solid fa-chart-column"></i>
                Threat Score Breakdown
            </h3>

            ${Object.entries(threat.score_breakdown || {})
                .map(([name, value]) =>
                    createInfoRow(
                        name,
                        `<span class="font-mono">+${value}</span>`
                    )
                ).join("")}

        </div>


        ${warningsHTML}

        ${recommendationsHTML}

    `;


    /* ============================= */
    /* ANIMATE EMAIL GAUGE           */
    /* ============================= */

    const circle =
        document.getElementById("email-gauge-progress");

    const scoreElement =
        document.getElementById("email-score-number");

    if (circle && scoreElement) {

        const radius = 85;
        const circumference = 2 * Math.PI * radius;

        circle.style.strokeDasharray = circumference;
        circle.style.strokeDashoffset = circumference;

        let current = 0;

        const timer = setInterval(() => {

            if (current >= score) {

                clearInterval(timer);

                scoreElement.textContent = score;

            } else {

                current++;

                scoreElement.textContent = current;

            }

        }, 15);

        const offset =
            circumference -
            (score / 100) * circumference;

        setTimeout(() => {

            circle.style.strokeDashoffset = offset;

        }, 200);

    }
}


/* ============================= */
/* CLEAR EMAIL SCANNER            */
/* ============================= */

function clearEmailScanner() {

    document.getElementById("emailFrom").value = "";
    document.getElementById("emailSubject").value = "";
    document.getElementById("emailInput").value = "";

    document.getElementById("emailResult").innerHTML = "";

    window.latestEmailScan = null;
}


/* ============================= */
/* STUBS (implement in other files or expand) */
/* ============================= */

function downloadReport(format) {
    if (!window.latestScan) {
        alert("Please run a scan first before downloading a report.");
        return;
    }
    alert(`Generating ${format.toUpperCase()} report... (connect to your backend PDF/CSV endpoint)`);
}

function showAnalytics() {
    alert("Analytics dashboard coming soon!");
}

/* ============================= */
/* INIT                          */
/* ============================= */

window.onload = () => {
    loadHistory();
};


/* ============================= */
/* EMAIL SCREENSHOT LISTENER     */
/* ============================= */

document.addEventListener("DOMContentLoaded", function () {

    const screenshotInput =
        document.getElementById("emailScreenshot");

    if (!screenshotInput) {
        return;
    }

    screenshotInput.addEventListener(
        "change",
        function () {

            const file = this.files[0];

            if (!file) {
                return;
            }

            console.log(
                "Email screenshot selected:",
                file.name
            );

            // OCR will be added in the next step.
        }
    );

});