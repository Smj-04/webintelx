const express = require("express");
const router = express.Router();
const { runTraceroute } = require("../controllers/tracerouteController");

router.post("/", runTraceroute);

module.exports = router;
