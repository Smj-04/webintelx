const leakcheckPublic = require("../utils/leakcheckPublic");

exports.checkLeak = async (req, res) => {
  const { value } = req.body;

  console.log("📥 [LeakCheck API] Request body:", req.body);

  if (!value) {
    console.warn("⚠️ [LeakCheck] Missing value");
    return res.status(400).json({ error: "Email or domain required" });
  }

  const result = await leakcheckPublic(value);

  res.json({
    module: "LeakCheck (Public)",
    checked: value,
    ...result
  });
};
