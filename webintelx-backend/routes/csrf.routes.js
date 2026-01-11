const express = require("express");
const router = express.Router();
const csrfController = require("../controllers/csrf.controller");

// CSRF scan route
router.post("/scan", csrfController.scanCSRF);

// ✅ EXPORT ROUTER DIRECTLY
module.exports = router;
