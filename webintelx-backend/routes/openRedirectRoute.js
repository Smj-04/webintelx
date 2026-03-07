const express = require("express");
const router = express.Router();
const { openRedirectScan } = require("../controllers/openRedirectController");

router.post("/", openRedirectScan);

module.exports = router;