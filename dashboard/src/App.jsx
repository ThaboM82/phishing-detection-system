import { useState } from 'react'

function App() {
  const [urlInput, setUrlInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleScan = async (e) => {
    e.preventDefault()
    if (!urlInput.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch('https://phishing-detection-api-dp0h.onrender.com/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: urlInput }),
      })

      if (!response.ok) {
        throw new Error('Failed to analyze the URL. Please try again.')
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err.message || 'An unexpected error occurred.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-white font-sans flex flex-col justify-between">
      {/* Header */}
      <header className="border-b border-slate-800 py-4 px-6 flex justify-between items-center max-w-7xl mx-auto w-full">
        <div className="flex items-center gap-2 font-bold text-xl text-blue-500">
          <span>🛡️</span> PhishGuard AI
        </div>
        <nav className="flex gap-6 text-sm text-slate-300 items-center">
          <a href="#features" className="hover:text-white transition">Features</a>
          <a href="#how-it-works" className="hover:text-white transition">How it works</a>
          <button className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition">
            Get Started
          </button>
        </nav>
      </header>

      {/* Hero / Scanner Section */}
      <main className="max-w-4xl mx-auto px-6 py-16 text-center flex-1 flex flex-col justify-center items-center">
        <span className="bg-blue-900/50 text-blue-400 border border-blue-800 text-xs px-3 py-1 rounded-full uppercase tracking-wider mb-6">
          New: ML Powered Phishing Detection
        </span>
        <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight mb-4">
          Detect Phishing <br />
          <span className="text-blue-500">Instantly with AI</span>
        </h1>
        <p className="text-slate-400 text-lg max-w-2xl mb-8">
          Protect yourself from scams using advanced machine learning models trained on millions of cyber threats.
        </p>

        {/* URL Scanner Form */}
        <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-3 w-full max-w-2xl mb-8">
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="Enter URL to check (e.g., https://suspicious-link.com)..."
            className="flex-1 px-4 py-3 rounded-lg border border-slate-700 bg-slate-800 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {loading ? 'Scanning...' : 'Scan Link'}
          </button>
        </form>

        {/* Error Feedback */}
        {error && (
          <div className="w-full max-w-2xl p-4 bg-red-900/30 border border-red-700 text-red-200 rounded-lg text-left mb-6">
            ⚠️ {error}
          </div>
        )}

        {/* API Results Display */}
        {result && (
          <div className="w-full max-w-2xl p-6 bg-slate-800 border border-slate-700 rounded-xl text-left shadow-lg">
            <h3 className="text-lg font-semibold mb-2 border-b border-slate-700 pb-2">Analysis Results</h3>
            <div className="flex justify-between items-center my-3">
              <span className="text-slate-400">Verdict:</span>
              <span className={`font-bold px-3 py-1 rounded ${result.is_phishing ? 'bg-red-900/50 text-red-400 border border-red-800' : 'bg-green-900/50 text-green-400 border border-green-800'}`}>
                {result.is_phishing ? 'PHISHING DETECTED' : 'LEGITIMATE'}
              </span>
            </div>
            {result.phishing_probability !== undefined && (
              <div className="flex justify-between items-center my-2 text-sm text-slate-300">
                <span>Threat Risk Score:</span>
                <span className="font-mono">{(result.phishing_probability * 100).toFixed(1)}%</span>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-6 text-center text-sm text-slate-500">
        © 2026 PhishGuard AI. All rights reserved.
      </footer>
    </div>
  )
}

export default App