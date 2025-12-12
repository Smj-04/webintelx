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

app.use(cors());
app.use(express.json());


app.use("/api/nslookup", nslookupRoute);
app.use("/api/whois", whoisRoute);
app.use("/api/ping", pingRoute);
app.use("/api/traceroute", tracerouteRoute);
app.use("/api/portscan", portscanRoute);
app.use("/api/headers", headersRoute);
app.use("/api/ssl", sslRoute);
app.use("/api/quickscan", quickScanRoute);

const PORT = 5000;

app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
