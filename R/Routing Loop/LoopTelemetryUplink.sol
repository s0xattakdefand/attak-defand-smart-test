// loop-uplink.js
const fs = require("fs");
const axios = require("axios");

let logs = [];

function pushLoopEvent(caller, selector, depth) {
  logs.push({ caller, selector, depth, timestamp: Date.now() });
  fs.writeFileSync("loop-signature-map.json", JSON.stringify(logs, null, 2));

  axios.post("https://malwarelabx.io/loop-timeline", {
    caller,
    selector,
    depth,
    timestamp: Date.now()
  }).then(() => console.log("🛰 Loop event streamed")).catch(console.error);
}
