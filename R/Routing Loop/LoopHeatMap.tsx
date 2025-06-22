import { HeatMapGrid } from 'react-grid-heatmap';

export default function LoopHeatmap({ data }) {
  const selectors = [...new Set(data.map(x => x.selector))];
  const callers = [...new Set(data.map(x => x.caller))];

  const matrix = callers.map(caller =>
    selectors.map(sel => {
      const entry = data.find(x => x.caller === caller && x.selector === sel);
      return entry ? entry.depth : 0;
    })
  );

  return (
    <div className="bg-zinc-900 text-green-300 p-4">
      <h2 className="text-xl font-bold mb-3">🔁 Loop Depth Heatmap</h2>
      <HeatMapGrid
        data={matrix}
        xLabels={selectors}
        yLabels={callers}
        cellStyle={(x, y, val) => ({
          background: val > 10 ? '#ff4444' : val > 5 ? '#ffaa00' : '#333',
          color: 'white',
        })}
      />
    </div>
  );
}
