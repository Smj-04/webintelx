const express = require("express");
const router = express.Router();
const { checkClickjacking } = require("../controllers/clickjackingController");

router.post("/clickjacking", checkClickjacking);

module.exports = router;
