const express = require("express");
const router = express.Router();
const { whatwebScan } = require("../controllers/whatwebController");

router.post("/", whatwebScan);

module.exports = router;
