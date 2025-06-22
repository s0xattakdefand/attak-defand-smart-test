import { useState } from "react"

export default function RaceUpload() {
  const [log, setLog] = useState("")

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return

    const text = await file.text()
    const result = await fetch("/api/foundry-run", {
      method: "POST",
      body: text,
    }).then(res => res.text())

    setLog(result)
  }

  return (
    <div className="p-6">
      <h2 className="text-xl font-bold mb-4">🎯 Race Replay Test Runner</h2>
      <input type="file" accept=".t.sol" onChange={handleUpload} />
      <pre className="mt-4 bg-black text-green-400 p-4 rounded overflow-auto max-h-96">
        {log || "Upload a test and view output here..."}
      </pre>
    </div>
  )
}
