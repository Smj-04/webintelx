import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({});

// Read input from stdin
let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", async () => {
  try {
    const { scanType, scanData } = JSON.parse(input);

    const prompt = `
  You are a cybersecurity assistant helping beginners understand web security scan results.

  Scan Type:
  ${scanType}

  Scan Results:
  ${JSON.stringify(scanData, null, 2)}

  Your job:
  Explain the scan results clearly and professionally.

  Rules:
  - Do NOT invent findings.
  - Only use information present in the scan data.
  - Highlight only important issues.
  - Use short bullet points.
  - Avoid technical jargon where possible.
  - Provide clear actionable advice.
  - Maximum 250 words.

  Follow this format EXACTLY.
  Do not change section titles.

  1. EXECUTIVE SUMMARY
  Brief overview of the scan purpose and overall security posture.

  2. METHODOLOGY
  Mention that automated reconnaissance and vulnerability scanning tools were used following OWASP Top 10 guidelines.

  3. KEY FINDINGS
  List the most important findings detected in the scan.
  Include risk levels if identifiable.

  4. REMEDIATION STEPS
  Provide clear fixes or improvements based on the findings.

  5. RECOMMENDATIONS
  General security improvements to strengthen the system.
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
