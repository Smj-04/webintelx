// controllers/csrfController.js

const { runCSRFScan } = require("../utils/csrf/csrfScanner");

exports.csrfScan = async (req, res) => {
  try {
    const { url } = req.body;
    const result = await runCSRFScan(url);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

