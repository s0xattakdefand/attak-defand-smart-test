import { useState } from 'react'
import { ethers } from 'ethers'

export default function VerifySignature() {
  const [message, setMessage] = useState('')
  const [signature, setSignature] = useState('')
  const [valid, setValid] = useState<boolean | null>(null)

  const verify = async () => {
    const signer = await ethers.utils.verifyMessage(message, signature)
    setValid(!!signer)
  }

  return (
    <div className="p-6 bg-white shadow rounded-xl max-w-lg mx-auto">
      <h2 className="text-xl font-bold mb-4">🔐 Verify Signed Message</h2>
      <textarea className="w-full p-2 border rounded" rows={3} placeholder="Paste message" onChange={e => setMessage(e.target.value)} />
      <textarea className="w-full p-2 mt-2 border rounded" rows={3} placeholder="Paste signature" onChange={e => setSignature(e.target.value)} />
      <button className="mt-4 px-4 py-2 bg-black text-white rounded" onClick={verify}>Verify</button>
      {valid !== null && (
        <div className={`mt-2 font-semibold ${valid ? 'text-green-600' : 'text-red-600'}`}>
          {valid ? '✅ Signature is valid' : '❌ Invalid signature'}
        </div>
      )}
    </div>
  )
}
