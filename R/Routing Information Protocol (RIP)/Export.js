const fs = require("fs");

function exportRouteGraph(entries) {
  fs.writeFileSync("rip-graph.json", JSON.stringify(entries, null, 2));
}
