function createInfoRow(label, value) {
    return `
        <div class="info-row">
            <span class="label">${label}</span>
            <span class="value">${value}</span>
        </div>
    `;
}

function createSSLCard(ssl) {
    return `
        <div class="dashboard-card">
            <h3>🔒 SSL Certificate</h3>

            ${createInfoRow(
                "Status",
                ssl.ssl_available ? "✅ Valid" : "❌ Invalid"
            )}

            ${createInfoRow("Issuer", ssl.issuer)}

            ${createInfoRow("Days Left", ssl.days_remaining)}

            ${createInfoRow("Expiry", ssl.expiry_date)}
        </div>
    `;
}

function createDNSCard(dns) {
    return `
        <div class="dashboard-card">
            <h3>🌐 DNS Information</h3>

            ${createInfoRow("MX Records", dns["MX Records"].length)}

            ${createInfoRow("A Records", dns["A Records"].length)}

            ${createInfoRow("NS Records", dns["NS Records"].length)}
        </div>
    `;
}

function createWhoisCard(whois) {

    const years = Math.floor(whois.domain_age_days / 365);

    return `
        <div class="dashboard-card">

            <h3>🌍 WHOIS Information</h3>

            ${createInfoRow("Domain Age", years + " Years")}

            ${createInfoRow("Country", whois.country)}

            ${createInfoRow("Registrar", whois.registrar)}

            ${createInfoRow("Expiry", whois.days_until_expiry + " Days")}

        </div>
    `;
}

function createKeywordCard(keyword) {

    return `
        <div class="dashboard-card">

            <h3>🚩 Keyword Analysis</h3>

            ${createInfoRow("Matches", keyword.total_matches)}

            ${createInfoRow(
                "Keywords",
                keyword.matched_keywords.length > 0
                    ? keyword.matched_keywords.join(", ")
                    : "None"
            )}

        </div>
    `;
}

function createWarnings(warnings) {

    if (!warnings || warnings.length === 0) {

        return `
            <div class="panel">
                <h3>⚠ Warnings</h3>
                <p>✅ No warnings detected.</p>
            </div>
        `;
    }

    return `
        <div class="panel">

            <h3>⚠ Warnings</h3>

            <ul>

                ${warnings.map(w => `<li>${w}</li>`).join("")}

            </ul>

        </div>
    `;
}

function createRecommendations(recommendations) {

    if (!recommendations || recommendations.length === 0) {

        return `
            <div class="panel">
                <h3>💡 Recommendations</h3>
                <p>✅ Safe to browse.</p>
            </div>
        `;
    }

    return `
        <div class="panel">

            <h3>💡 Recommendations</h3>

            <ul>

                ${recommendations.map(r => `<li>${r}</li>`).join("")}

            </ul>

        </div>
    `;
}

function saveHistory(data){

    let history =
        JSON.parse(localStorage.getItem("scanHistory")) || [];

    history.unshift({

        url:data.url,

        prediction:data.machine_learning.prediction,

        score:data.threat_analysis.overall_score,

        date:new Date().toLocaleString()

    });

    history = history.slice(0,10);

    localStorage.setItem(

        "scanHistory",

        JSON.stringify(history)

    );

}
list.innerHTML += `

<div class="history-item"

onclick="reloadURL('${item.url}')">

<div>

<div class="history-url">

${item.url}

</div>

<div>

${item.date}

</div>

</div>

<div>

<div class="history-status ${
item.prediction==="PHISHING"
?
"status-phishing"
:
"status-safe"
}">

${item.prediction}

</div>

<div style="margin-top:8px;
font-size:13px;
text-align:center;">

Score : ${item.score}/100

</div>

</div>

</div>

`;

function reloadURL(url){

    document.getElementById("urlInput").value = url;

    analyzeURL();

}
function clearHistory(){

    localStorage.removeItem("scanHistory");

    loadHistory();

}
function loadHistory() {

    const history =
        JSON.parse(localStorage.getItem("scanHistory")) || [];

    const list = document.getElementById("historyList");

    if (history.length === 0) {

        list.innerHTML = "<p class='empty-history'>No scans yet.</p>";

        return;

    }

    list.innerHTML = "";

    history.forEach(item => {

        list.innerHTML += `
        <div class="history-item">
            <div>
                <div class="history-url">${item.url}</div>
                <div>${item.date}</div>
            </div>

            <div class="history-status ${
                item.prediction === "PHISHING"
                ? "status-phishing"
                : "status-safe"
            }">

                ${item.prediction}

            </div>
        </div>
        `;

    });

}
async function analyzeURL() {

    const url = document.getElementById("urlInput").value.trim();

    if (!url) {

        alert("Please enter a URL");

        return;

    }

    document.getElementById("loading").style.display = "block";

    document.getElementById("result").innerHTML = "";

    try {

        const response = await fetch("http://127.0.0.1:5000/analyze", {

            method: "POST",

            headers: {

                "Content-Type": "application/json"

            },

            body: JSON.stringify({

                url: url

            })

        });

        const data = await response.json();
        saveHistory(data);
        window.latestScan = data;
        loadHistory();

        document.getElementById("loading").style.display = "none";

        if (data.status === "FAILED") {

            alert(data.message);

            return;

        }

        const prediction = data.machine_learning.prediction;

        const predictionColor =
            prediction === "PHISHING"
                ? "#ef4444"
                : "#22c55e";

        const confidence = data.machine_learning.confidence;

        const threat = data.threat_analysis.overall_score;

        const verdictColor =
    threat < 25
        ? "#22c55e"
        : threat < 50
        ? "#facc15"
        : threat < 75
        ? "#f97316"
        : "#ef4444";

        document.getElementById("result").innerHTML = `

<div class="summary-card">

<div class="summary-layout">

<div class="summary-left">

<h2 style="color:${predictionColor}">
${prediction}
</h2>

<p>

<strong>Confidence:</strong>

${confidence}%

</p>

<div class="progress">

<div
class="progress-fill"
style="width:${confidence}%">

</div>

</div>

<p>

<strong>Verdict :</strong>

<span
style="color:${verdictColor};
font-weight:bold;">

${data.threat_analysis.verdict}

</span>

</p>

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
id="gauge-progress"
class="gauge-progress"
cx="110"
cy="110"
r="85">
</circle>

</svg>

<div class="gauge-text">

<h1 id="score-number">0</h1>

<span>/100</span>

</div>

</div>

<h3>Threat Score</h3>

</div>

</div>

</div>

<div class="dashboard-grid">

    ${createSSLCard(data.ssl.data)}

    ${createDNSCard(data.dns.data)}

    ${createWhoisCard(data.whois)}

    ${createKeywordCard(data.keywords.data)}

</div>

${createWarnings(data.threat_analysis.warnings)}

${createRecommendations(data.threat_analysis.recommendations)}

`;

// ===============================
// Threat Gauge Animation
// ===============================

const circle = document.getElementById("gauge-progress");

const radius = 85;

const circumference = 2 * Math.PI * radius;

circle.style.strokeDasharray = circumference;

circle.style.strokeDashoffset = circumference;

const scoreElement =
document.getElementById("score-number");

let current = 0;

const timer = setInterval(() => {

    if(current >= threat){

        clearInterval(timer);

    }
    else{

        current++;

        scoreElement.innerHTML = current;

    }

},15);


// Change color based on score

if (threat < 25) {

    circle.style.stroke = "#22c55e";

}
else if (threat < 50) {

    circle.style.stroke = "#facc15";

}
else if (threat < 75) {

    circle.style.stroke = "#f97316";

}
else {

    circle.style.stroke = "#ef4444";

}


// Animate

const offset =
    circumference -
    (threat / 100) * circumference;

setTimeout(() => {

    circle.style.strokeDashoffset = offset;

}, 200);

    }

    catch(error){

    document.getElementById("loading").style.display="none";

    console.error(error);

    alert(error.message);

}

}
window.onload=()=>{

    loadHistory();

};