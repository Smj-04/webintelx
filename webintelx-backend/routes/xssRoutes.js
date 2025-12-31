const express = require("express");
const router = express.Router();
const { runXSSScan } = require("../controllers/xssController");

router.post("/xss", runXSSScan);

module.exports = router;
