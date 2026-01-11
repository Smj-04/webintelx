const emailRepCheck = require("../utils/emailRepCheck");

exports.checkEmailRep = async (req, res) => {
  const { email } = req.body;

  console.log("📥 [EmailRep API] Request body:", req.body);

  if (!email) {
    console.warn("⚠️ [EmailRep] Missing email");
    return res.status(400).json({ error: "Email required" });
  }

  const result = await emailRepCheck(email);

  res.json({
    module: "Email Reputation",
    email,
    ...result
  });
};
