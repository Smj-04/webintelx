const axios = require("axios");

exports.scanHeaders = async (req, res) => {
  const { url } = req.body;

  if (!url.startsWith("http")) return res.json({ error: "Include http:// or https://" });

  try {
    const response = await axios.get(url);

    res.json({
      success: true,
      headers: response.headers
    });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
};
