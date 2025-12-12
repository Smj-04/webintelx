const runCommand = require("../utils/runCommand");

exports.runWhois = async (req, res) => {
  const { url } = req.body;

  if (!url) return res.status(400).json({ error: "URL is required" });

  try {
    const output = await runCommand(`whois ${url}`);
    res.json({ success: true, output });
  } catch (error) {
    res.json({ success: false, error });
  }
};
