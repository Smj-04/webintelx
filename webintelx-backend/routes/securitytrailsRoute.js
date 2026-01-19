const express = require("express");
const router = express.Router();
const { securityTrailsScan } = require("../controllers/securitytrailsController");

router.post("/securitytrails", securityTrailsScan);

module.exports = router;
