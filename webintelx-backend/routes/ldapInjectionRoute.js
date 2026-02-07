const express = require("express");
const router = express.Router();
const { scanLDAPInjection } = require("../controllers/ldapInjectionController");

router.post("/ldap-injection", scanLDAPInjection);

module.exports = router;
