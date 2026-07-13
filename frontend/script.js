async function analyzeURL() {

    const url = document.getElementById("urlInput").value;

    if (url === "") {

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

        document.getElementById("loading").style.display = "none";

        document.getElementById("result").innerHTML =

        `
        <div class="card">

            <h2>Prediction</h2>

            <h3>${data.machine_learning.prediction}</h3>

            <p><b>Confidence:</b> ${data.machine_learning.confidence}%</p>

            <p><b>Threat Score:</b> ${data.threat_analysis.overall_score}/100</p>

            <p><b>Verdict:</b> ${data.threat_analysis.verdict}</p>

        </div>
        `;

    }

    catch(error){

        document.getElementById("loading").style.display="none";

        alert(error);

    }

}