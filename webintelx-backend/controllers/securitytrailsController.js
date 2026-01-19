const { getSecurityTrailsData } = require("../utils/securitytrails");

exports.securityTrailsScan = async (req, res) => {
  try {
    const { domain } = req.body;

    if (!domain || typeof domain !== "string") {
    return res.status(400).json({
        success: false,
        error: "Valid domain is required"
    });
}


    const data = await getSecurityTrailsData(domain);

    res.json({
      module: "SecurityTrails",
      scanType: "passive",
      success: true,
      data
    });

} catch (err) {
  const status = err.response?.status || 500;

  res.status(status).json({
    module: "SecurityTrails",
    success: false,
    error: err.response?.data?.message || "SecurityTrails request blocked or forbidden"
  });
}
};
