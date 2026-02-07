require("dotenv").config();
const express = require("express");
const cors = require("cors");

const nslookupRoute = require("./routes/nslookupRoute");
const whoisRoute = require("./routes/whoisRoute");
const pingRoute = require("./routes/pingRoute");
const tracerouteRoute = require("./routes/tracerouteRoute");
const portscanRoute = require("./routes/portscanRoute");
const headersRoute = require("./routes/headersRoute");
const sslRoute = require("./routes/sslRoute");
const app = express();
const quickScanRoute = require("./routes/quickScanRoute");
const whatwebRoute = require("./routes/whatwebRoute");
const xssRoutes = require("./routes/xssRoutes");
const autoXssRoute = require("./routes/autoXssRoute");
const sqlmapRoute = require("./routes/sqlmapRoute");
const csrfRoutes = require("./routes/csrf.routes");
const securityTrailsRoute = require("./routes/securitytrailsRoute");
const reportRoute = require("./routes/reportRoute");

console.log("🚀 SERVER FILE PATH:", __filename);

app.use(cors());
app.use(express.json());
app.use("/api/whatweb", whatwebRoute);
app.use("/api/nslookup", nslookupRoute);
app.use("/api/whois", whoisRoute);
app.use("/api/ping", pingRoute);
app.use("/api/traceroute", tracerouteRoute);
app.use("/api/portscan", portscanRoute);
app.use("/api/headers", headersRoute);
app.use("/api/ssl", sslRoute);
app.use("/api/quickscan", quickScanRoute);
app.use("/api/fullscan", require("./routes/fullScanRoute"));
app.use("/api", xssRoutes);
app.use("/api", autoXssRoute);
app.use("/api", sqlmapRoute);
app.use("/api/report", reportRoute);

app.use("/api", require("./routes/aiReportRoute"));

app.use("/api/csrf", csrfRoutes);
app.use("/api", require("./routes/clickjackingRoute"));
app.use("/api", require("./routes/leakcheckRoute"));
app.use("/api", require("./routes/emailRepRoute"));
app.use("/api", require("./routes/commandInjectionRoute"));
app.use("/api", securityTrailsRoute);
app.use("/api", require("./routes/domXssRoute"));
app.use("/api", require("./routes/ldapInjectionRoute"));
app.use("/api", require("./routes/sstiRoute"));
app.use("/api", require("./routes/storedXssRoute"));
app.use("/api", require("./routes/csrfTokenRoute"));
app.use("/api", require("./routes/tokenAuthRoute"));
app.use("/api", require("./routes/idorRoute"));

const PORT = 5000;

app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});

console.log("Gemini Key Loaded:", process.env.GEMINI_API_KEY ? "YES" : "NO");
