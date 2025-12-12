const express = require("express");
const router = express.Router();
const { runPortScan } = require("../controllers/portscanController");

router.post("/", runPortScan);

module.exports = router;
