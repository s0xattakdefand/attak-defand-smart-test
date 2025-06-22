import { HeatMapGrid } from 'react-grid-heatmap';

export default function RPCScanHeatmap({ data }) {
  const chains = [...new Set(data.map(x => x.chainId.toString()))];
  const selectors = [...new Set(data.map(x => x.selector))];

  const matrix = chains.map(chain =>
    selectors.map(sel => {
      const match = data.find(d => d.chainId.toString() === chain && d.selector === sel);
      return match ? match.count : 0;
    })
  );

  return (
    <div className="p-4 bg-black text-green-400">
      <h2 className="text-lg font-bold mb-2">🛰 RPC Scan Heatmap</h2>
      <HeatMapGrid
        data={matrix}
        xLabels={selectors}
        yLabels={chains}
        cellStyle={(x, y, val) => ({
          background: val > 10 ? '#ff4444' : val > 5 ? '#ffaa00' : '#222',
          color: 'white',
        })}
      />
    </div>
  );
}
