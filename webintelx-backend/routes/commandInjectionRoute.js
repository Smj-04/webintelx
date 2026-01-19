const express = require("express");
const router = express.Router();
const { scanCommandInjection } = require("../controllers/commandInjectionController");

router.post("/command-injection", scanCommandInjection);

module.exports = router;
