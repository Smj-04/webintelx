import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({});

// Read input from stdin
let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", async () => {
  try {
    const { scanType, scanData } = JSON.parse(input);

    const prompt = `
You are a cybersecurity assistant for beginners.

The user ran a **Quick Security Scan** on a website.

Scan Type:
${scanType}

Scan Results:
${JSON.stringify(scanData, null, 2)}

Your task:
- Explain the results in simple but professional terms
-dont make it seem like an ai report and keep it professional
- Highlight **only the most important points**
- Avoid long paragraphs
- Avoid technical jargon where possible
-provide clear ,actionable advice
-dont make up any findings not in the scan data
-if tech stack in the results are outdated or vulnerable ,mention them in the report
Respond in this EXACT format:

1. EXECUTIVE SUMMARY
Scope and Objective: that identifies the systems, applications and networks being tested and the aim of testing.
Timeline and Date: denotes the date when the assessment was performed, and this will provide context to future reviews.
High-Level Findings: Gives an overview of the overall security posture and the major vulnerabilities that are identified.
Intended Audience: The writing style is business-friendly to the executives, board members and the clients.

2. METHODOLOGY
Tools: List vulnerability scanners and frameworks (e.g. Nessus, Qualys, or OpenVAS).
Testing Standards: This is internationally recognized standards e.g. OWASP top 10 or SANS top 25.
Assessment Approach: It is either a black-box, white-box or grey-box testing.

3. FINDINGS
Index of Vulnerabilities: The vulnerabilities are outlined, categorized and described.
Severity Ratings: Critical, High, Medium and Low to aid with prioritization of remediation.
Business Impact: How this or that vulnerability may have an impact on the confidentiality, integrity or availability of the data.

4. REMEDIATION STEPS
Actionable Fixes: Includes patch updates, secure configuration changes, or policy enforcement.
Quick Wins vs Long-Term Fixes: Makes known what can and must be done in the short run and what will need strategy.
Technical Evidence: Screenshots, packet captures or scan output that contains proof of all the funds.

5. COMPLIANCE MAPPING
Framework Alignment: Maps vulnerabilities to compliance standards directly (e.g. PCI DSS, HIPAA, or ISO 27001).
Audit-Ready Form: It means that it provides assurance that the report can be given to auditors, insurers or regulators without any alterations.
Vendor Assurance: Provides proof of due diligence for client security reviews.

6. RECCOMMENDATIONS
Prioritized Action Plan: A roadmap for remediation based on risk assessment and business priorities.
Security Best Practices: General advice on improving security posture beyond the identified vulnerabilities.


Do NOT use overly professional or corporate language.
Keep it clear and student-friendly.
make the report well structured with headings and sub headings
`;


    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
    });

    process.stdout.write(response.text);
  } catch (err) {
    process.stderr.write(err.message);
    process.exit(1);
  }
});
