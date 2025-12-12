const express = require("express");
const router = express.Router();

const { runNslookup } = require("../controllers/nslookupController");

router.post("/", runNslookup);

module.exports = router;
