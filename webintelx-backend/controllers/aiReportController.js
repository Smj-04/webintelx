const generateAIReport = require("../utils/geminiService");

exports.generateAIReport = async (req, res) => {
  const { scanType, scanData } = req.body;

  if (!scanType || !scanData) {
    return res.status(400).json({
      success: false,
      error: "scanType and scanData required",
    });
  }

  try {
    const report = await generateAIReport(scanType, scanData);

    res.json({
      success: true,
      aiReport: report,
    });
  } catch (err) {
    console.error("AI Report Error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to generate AI report",
    });
  }
};
