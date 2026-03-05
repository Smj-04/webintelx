// routes/csrfRoutes.js

const express = require("express");
const router = express.Router();
const csrfController = require("../controllers/csrfController");

router.post("/", csrfController.csrfScan);

module.exports = router;

