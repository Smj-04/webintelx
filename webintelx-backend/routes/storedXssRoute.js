const express = require("express");
const router = express.Router();
const { scanStoredXSS } = require("../controllers/storedXssController");

router.post("/stored-xss", scanStoredXSS);

module.exports = router;
