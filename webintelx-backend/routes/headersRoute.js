const express = require("express");
const router = express.Router();
const { scanHeaders } = require("../controllers/headersController");

router.post("/", scanHeaders);

module.exports = router;
