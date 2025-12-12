const tls = require("tls");

exports.scanSSL = (req, res) => {
  const { url } = req.body;

  if (!url) return res.status(400).json({ error: "URL is required" });

  const host = url.replace("https://", "").replace("http://", "");

  const socket = tls.connect(443, host, { servername: host }, () => {
    const cert = socket.getPeerCertificate();
    socket.end();

    res.json({
      success: true,
      certificate: cert
    });
  });

  socket.on("error", () => {
    res.json({ success: false, error: "Failed to fetch SSL certificate" });
  });
};
