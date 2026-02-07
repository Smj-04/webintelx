const express = require("express");
const router = express.Router();
const { scanCSRFToken } = require("../controllers/csrfTokenController");

router.post("/csrf-token", scanCSRFToken);

module.exports = router;
