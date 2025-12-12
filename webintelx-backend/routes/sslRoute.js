const express = require("express");
const router = express.Router();
const { scanSSL } = require("../controllers/sslController");

router.post("/", scanSSL);

module.exports = router;
