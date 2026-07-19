async function downloadReport(){

    if(!window.latestScan){

        alert("Analyze a URL first.");

        return;

    }

    const { jsPDF } = window.jspdf;

    const doc = new jsPDF();

    const report = window.latestScan;

    let y = 20;

    doc.setFontSize(20);

    doc.text("AI PHISHING DETECTION REPORT",20,y);

    y+=15;

    doc.setFontSize(11);

    doc.text("Generated : "+new Date().toLocaleString(),20,y);

    y+=10;

    doc.text("URL : "+report.url,20,y);

    y+=15;



    doc.setFontSize(15);

    doc.text("Machine Learning",20,y);

    y+=10;

    doc.setFontSize(11);

    doc.text("Prediction : "+report.machine_learning.prediction,20,y);

    y+=8;

    doc.text("Confidence : "+report.machine_learning.confidence+" %",20,y);

    y+=8;

    doc.text("Legitimate Probability : "+report.machine_learning.legitimate_probability+" %",20,y);

    y+=8;

    doc.text("Phishing Probability : "+report.machine_learning.phishing_probability+" %",20,y);

    y+=15;



    doc.setFontSize(15);

    doc.text("Threat Analysis",20,y);

    y+=10;

    doc.setFontSize(11);

    doc.text("Threat Score : "+report.threat_analysis.overall_score+"/100",20,y);

    y+=8;

    doc.text("Verdict : "+report.threat_analysis.verdict,20,y);

    y+=8;

    doc.text("Security Level : "+report.threat_analysis.security_level,20,y);

    y+=15;



    doc.setFontSize(15);

    doc.text("SSL Information",20,y);

    y+=10;

    doc.setFontSize(11);

    doc.text("Issuer : "+report.ssl.data.issuer,20,y);

    y+=8;

    doc.text("Expiry : "+report.ssl.data.expiry_date,20,y);

    y+=8;

    doc.text("Days Remaining : "+report.ssl.data.days_remaining,20,y);

    y+=15;



    doc.setFontSize(15);

    doc.text("WHOIS Information",20,y);

    y+=10;

    doc.setFontSize(11);

    doc.text("Registrar : "+report.whois.registrar,20,y);

    y+=8;

    doc.text("Country : "+report.whois.country,20,y);

    y+=8;

    doc.text("Domain Age : "+Math.floor(report.whois.domain_age_days/365)+" Years",20,y);

    y+=15;



    doc.setFontSize(15);

    doc.text("Warnings",20,y);

    y+=10;

    doc.setFontSize(11);

    if(report.threat_analysis.warnings.length){

        report.threat_analysis.warnings.forEach(w=>{

            doc.text("- "+w,25,y);

            y+=8;

        });

    }

    else{

        doc.text("No warnings.",20,y);

        y+=8;

    }



    y+=10;

    doc.setFontSize(15);

    doc.text("Recommendations",20,y);

    y+=10;

    doc.setFontSize(11);

    if(report.threat_analysis.recommendations.length){

        report.threat_analysis.recommendations.forEach(r=>{

            doc.text("- "+r,25,y);

            y+=8;

        });

    }

    else{

        doc.text("No recommendations.",20,y);

    }

    doc.save("AI_Phishing_Report.pdf");

}