import { GoogleGenAI } from "@google/genai";

// API key is automatically read from process.env.GEMINI_API_KEY
const ai = new GoogleGenAI({});

export async function generateAIReport(scanType, scanData) {
  try {
    const prompt = `
You are a cybersecurity expert.

Scan Type: ${scanType}

Scan Results:
${JSON.stringify(scanData, null, 2)}

Give:
1. Executive summary
2. Vulnerabilities found
3. Severity level
4. Recommended fixes
5. Overall risk rating (Low / Medium / High)

Keep it concise and professional.
`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
    });

    return response.text;
  } catch (err) {
    console.error("Gemini Error:", err);
    throw err;
  }
}
