const express = require("express");
const router = express.Router();
const { scanSSTI } = require("../controllers/sstiController");

router.post("/ssti", scanSSTI);

module.exports = router;
