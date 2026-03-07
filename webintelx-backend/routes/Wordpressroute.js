const express = require("express");
const router = express.Router();
const { scanWordPress } = require("../controllers/wordpressController");

/**
 * @route  POST /api/wordpress/scan
 * @desc   Scan a WordPress site for vulnerabilities (fully manual, no API key needed)
 * @body   { url: "https://example.com" }
 */
router.post("/scan", scanWordPress);

module.exports = router;