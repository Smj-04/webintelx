const express = require("express");
const router = express.Router();
const { scanDOMXSS } = require("../controllers/domXssController");

router.post("/dom-xss", scanDOMXSS);

module.exports = router;
