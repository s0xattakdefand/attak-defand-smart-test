const fs = require("fs");
const axios = require("axios");

async function pushRPCProbes() {
  const logs = JSON.parse(fs.readFileSync("rpc-scan-log.json", "utf8"));
  await axios.post("https://malwarelabx.io/rpc-probe-stream", logs);
  console.log("🛰 Synced RPC scan probes to MalwareLabX");
}

pushRPCProbes();
