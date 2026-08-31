const companyData = {

    "Google": {
        risk: "HIGH",
        emails: "24,800",
        passwords: "8,420",
        data: "Email addresses, passwords and credentials",
        recommendation: "Enable MFA, reset exposed credentials and monitor suspicious activity."
    },

    "Microsoft": {
        risk: "MEDIUM",
        emails: "12,500",
        passwords: "3,210",
        data: "Emails and authentication credentials",
        recommendation: "Review exposed accounts and enforce multi-factor authentication."
    },

    "Stellar Cloud Systems": {
        risk: "HIGH",
        emails: "18,430",
        passwords: "6,870",
        data: "Emails, passwords and employee information",
        recommendation: "Immediately rotate credentials and conduct a security audit."
    },

    "VertexFlow": {
        risk: "MEDIUM",
        emails: "7,250",
        passwords: "1,430",
        data: "Email addresses and user credentials",
        recommendation: "Monitor exposed accounts and strengthen authentication."
    },

    "Kinetico": {
        risk: "LOW",
        emails: "1,240",
        passwords: "320",
        data: "Email addresses",
        recommendation: "Continue monitoring dark web sources."
    },

    "Aurora Health": {
        risk: "HIGH",
        emails: "32,100",
        passwords: "9,450",
        data: "Emails, credentials and sensitive records",
        recommendation: "Perform immediate incident response and credential rotation."
    },

    "Nimbus Retail": {
        risk: "MEDIUM",
        emails: "9,830",
        passwords: "2,110",
        data: "Customer emails and passwords",
        recommendation: "Reset affected credentials and improve account security."
    },

    "Orbit Fintech": {
        risk: "HIGH",
        emails: "15,700",
        passwords: "5,320",
        data: "Financial account credentials",
        recommendation: "Immediately investigate the breach and secure affected accounts."
    }

};


function selectCompany(company) {

    document.getElementById("companyInput").value = company;

    analyzeCompany();

}


function analyzeCompany() {

    const input = document.getElementById("companyInput");

    const company = input.value.trim();

    const result = document.getElementById("result");


    if (company === "") {

        alert("Please enter a company name.");

        return;

    }


    let data = companyData[company];


    // If company is not in demo dataset
    if (!data) {

        data = {

            risk: "UNKNOWN",

            emails: "No data",

            passwords: "No data",

            data: "No matching records found in the demo dataset",

            recommendation:
                "No confirmed breach was found in this simulated dataset. Continue monitoring."

        };

    }


    result.classList.remove("hidden");


    result.innerHTML = `

        <h2>${company}</h2>

        <p>
            <strong>Risk Level:</strong>
            ${data.risk}
        </p>

        <p>
            <strong>Leaked Emails:</strong>
            ${data.emails}
        </p>

        <p>
            <strong>Leaked Passwords:</strong>
            ${data.passwords}
        </p>

        <p>
            <strong>Potential Data Leak:</strong>
            ${data.data}
        </p>

        <p>
            <strong>AI Recommendation:</strong>
            ${data.recommendation}
        </p>

    `;


    result.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });

}