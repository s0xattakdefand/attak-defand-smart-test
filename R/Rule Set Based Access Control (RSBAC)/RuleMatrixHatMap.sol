import { HeatMapGrid } from 'react-grid-heatmap';

export default function RuleMatrixHeatmap({ matrix }) {
  const roles = Object.keys(matrix);
  const selectors = [...new Set(Object.values(matrix).flatMap(Object.keys))];

  const data = roles.map(role =>
    selectors.map(sel => matrix[role][sel] || 0)
  );

  return (
    <div className="bg-black p-4 text-green-300">
      <h2 className="text-xl font-bold mb-2">📡 Selector x Rule Match Heatmap</h2>
      <HeatMapGrid
        data={data}
        xLabels={selectors}
        yLabels={roles}
        cellStyle={(_, __, val) => ({
          background: val > 10 ? "#ff4444" : val > 5 ? "#ffaa00" : "#333",
          color: "white",
        })}
      />
    </div>
  );
}
