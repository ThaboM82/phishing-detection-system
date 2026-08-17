import { useState } from 'react'

function App() {
  const [activeTab, setActiveTab] = useState('url')
  const [urlInput, setUrlInput] = useState('')
  const [messageInput, setMessageInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleScan = async (e) => {
    e.preventDefault()
    
    const payload = activeTab === 'url' ? { url: urlInput } : { text: messageInput }
    if (activeTab === 'url' && !urlInput.trim()) return
    if (activeTab === 'message' && !messageInput.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch('https://phishing-detection-api-dp0h.onrender.com/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })

      if (!response.ok) throw new Error('Analysis failed. Please check backend status.')

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err.message || 'Error connecting to API.')
    } finally {
      setLoading(false)
    }
  }

  const features = [
    { id: 'url', title: 'URL Scanner', icon: '🔗', desc: 'Instantly check links for malicious intent and phishing red flags.' },
    { id: 'message', title: 'Message Analyzer', icon: '✉️', desc: 'Analyze suspicious emails and SMS messages using advanced AI models.' },
    { id: 'file', title: 'File Analyzer', icon: '📁', desc: 'Scan documents and executables securely for zero-day malware.' },
    { id: 'assistant', title: 'AI Chat Assistant', icon: '🤖', desc: 'Ask our AI assistant about cyber threats in real-time.' },
    { id: 'risk', title: 'Risk Scoring', icon: '📊', desc: 'Get comprehensive threat scores and detailed explanations.' },
  ]

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0f172a', color: '#ffffff', fontFamily: 'system-ui, sans-serif', padding: '20px', boxSizing: 'border-box' }}>
      
      {/* Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '20px', borderBottom: '1px solid #334155', maxWidth: '1000px', margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }} onClick={() => setActiveTab('url')}>
          <span style={{ fontSize: '1.5rem' }}>🛡️</span>
          <h2 style={{ color: '#3b82f6', margin: 0, fontSize: '1.5rem', fontWeight: 'bold' }}>PhishGuard AI</h2>
        </div>
        <nav style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <button 
            type="button"
            onClick={() => setActiveTab('url')}
            style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '14px', fontWeight: '500' }}
          >
            Features
          </button>
          <button 
            type="button"
            style={{ backgroundColor: '#2563eb', color: '#ffffff', padding: '8px 16px', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: '600', fontSize: '14px' }}
          >
            Get Started
          </button>
        </nav>
      </header>

      {/* Main Content */}
      <main style={{ maxWidth: '900px', margin: '40px auto', textAlign: 'center' }}>
        
        {/* Hero Section */}
        <div style={{ marginBottom: '40px' }}>
          <span style={{ backgroundColor: '#1e3a8a', color: '#60a5fa', border: '1px solid #1d4ed8', padding: '4px 12px', borderRadius: '20px', fontSize: '12px', textTransform: 'uppercase' }}>
            New: GPT-4 Powered Phishing Detection
          </span>
          <h1 style={{ fontSize: '2.75rem', fontWeight: '800', marginTop: '16px', marginBottom: '12px', lineHeight: '1.2' }}>
            Detect Phishing <br />
            <span style={{ color: '#3b82f6' }}>Instantly with AI</span>
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '1.1rem', maxWidth: '600px', margin: '0 auto' }}>
            Protect yourself from scams using advanced machine learning models trained on millions of cyber threats.
          </p>
        </div>

        {/* Dynamic Tool Input Box */}
        <div style={{ backgroundColor: '#1e293b', padding: '28px', borderRadius: '12px', border: '1px solid #334155', marginBottom: '40px', boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.3)' }}>
          <h3 style={{ margin: '0 0 16px 0', color: '#60a5fa', fontSize: '1.1rem', textAlign: 'left' }}>
            Active Tool: {features.find(f => f.id === activeTab)?.title || 'URL Scanner'}
          </h3>

          {activeTab === 'url' && (
            <form onSubmit={handleScan} style={{ display: 'flex', gap: '12px' }}>
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Enter URL to check (e.g., https://example.com)..."
                required
                style={{ flex: '1', padding: '14px 18px', borderRadius: '8px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#ffffff', fontSize: '16px', outline: 'none' }}
              />
              <button
                type="submit"
                disabled={loading}
                style={{ backgroundColor: '#2563eb', color: '#ffffff', padding: '14px 28px', border: 'none', borderRadius: '8px', cursor: 'pointer', fontSize: '16px', fontWeight: 'bold' }}
              >
                {loading ? 'Scanning...' : 'Scan Link'}
              </button>
            </form>
          )}

          {activeTab === 'message' && (
            <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <textarea
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Paste suspicious email body or SMS message text here..."
                rows={4}
                required
                style={{ width: '100%', padding: '14px 18px', borderRadius: '8px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#ffffff', fontSize: '15px', outline: 'none', boxSizing: 'border-box' }}
              />
              <button
                type="submit"
                disabled={loading}
                style={{ backgroundColor: '#2563eb', color: '#ffffff', padding: '12px 24px', border: 'none', borderRadius: '8px', cursor: 'pointer', fontSize: '16px', fontWeight: 'bold', alignSelf: 'flex-end' }}
              >
                {loading ? 'Analyzing...' : 'Analyze Message'}
              </button>
            </form>
          )}

          {activeTab === 'file' && (
            <div style={{ padding: '30px', border: '2px dashed #475569', borderRadius: '8px', color: '#94a3b8' }}>
              <p style={{ fontSize: '1.2rem', margin: '0 0 8px 0' }}>📁 Drag & drop suspicious files here</p>
              <p style={{ fontSize: '0.85rem', margin: 0 }}>Supported formats: .pdf, .docx, .exe, .eml (Max size: 10MB)</p>
            </div>
          )}

          {activeTab === 'assistant' && (
            <div style={{ textAlign: 'left', color: '#94a3b8' }}>
              <p style={{ margin: '0 0 12px 0' }}>🤖 Ask PhishGuard AI Assistant about security advisories:</p>
              <input
                type="text"
                placeholder="Ask a question (e.g., How do I identify spoofed headers?)..."
                style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#ffffff', fontSize: '15px', boxSizing: 'border-box' }}
              />
            </div>
          )}

          {activeTab === 'risk' && (
            <div style={{ textAlign: 'left', color: '#94a3b8' }}>
              <p style={{ margin: 0 }}>📊 Enter any URL above or upload a message to generate threat metrics and heuristic breakdowns.</p>
            </div>
          )}
        </div>

        {/* Error Feedback */}
        {error && (
          <div style={{ backgroundColor: '#7f1d1d', color: '#fca5a5', padding: '16px', borderRadius: '8px', textAlign: 'left', marginBottom: '30px', border: '1px solid #991b1b' }}>
            ⚠️ <strong>Error:</strong> {error}
          </div>
        )}

        {/* Scan Results Output */}
        {result && (
          <div style={{ backgroundColor: '#1e293b', padding: '24px', borderRadius: '12px', border: '1px solid #334155', textAlign: 'left', marginBottom: '40px' }}>
            <h3 style={{ margin: '0 0 16px 0', borderBottom: '1px solid #334155', paddingBottom: '12px', fontSize: '1.2rem' }}>
              Analysis Results
            </h3>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span style={{ color: '#94a3b8' }}>Verdict:</span>
              <span style={{
                padding: '6px 14px',
                borderRadius: '6px',
                fontWeight: 'bold',
                fontSize: '14px',
                backgroundColor: result.is_phishing ? '#7f1d1d' : '#14532d',
                color: result.is_phishing ? '#fca5a5' : '#86efac',
                border: result.is_phishing ? '1px solid #991b1b' : '1px solid #166534'
              }}>
                {result.is_phishing ? '🚨 PHISHING DETECTED' : '✅ LEGITIMATE'}
              </span>
            </div>
            {result.phishing_probability !== undefined && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#94a3b8' }}>Risk Score:</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 'bold', fontSize: '16px' }}>
                  {(result.phishing_probability * 100).toFixed(1)}%
                </span>
              </div>
            )}
          </div>
        )}

        {/* FULLY INTERACTIVE FEATURE CARDS */}
        <h2 style={{ fontSize: '1.75rem', fontWeight: 'bold', marginBottom: '8px' }}>Powerful Features</h2>
        <p style={{ color: '#94a3b8', marginBottom: '24px' }}>Click any card below to open its scanner mode.</p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
          {features.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setActiveTab(item.id)
                window.scrollTo({ top: 180, behavior: 'smooth' })
              }}
              style={{
                backgroundColor: '#1e293b',
                padding: '24px',
                borderRadius: '12px',
                border: activeTab === item.id ? '2px solid #3b82f6' : '1px solid #334155',
                textAlign: 'left',
                cursor: 'pointer',
                color: '#ffffff',
                transition: 'all 0.2s ease',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}
            >
              <div style={{ fontSize: '2rem' }}>{item.icon}</div>
              <h3 style={{ margin: 0, fontSize: '1.2rem', color: '#ffffff', fontWeight: '600' }}>{item.title}</h3>
              <p style={{ margin: 0, fontSize: '0.9rem', color: '#94a3b8', lineHeight: '1.4' }}>{item.desc}</p>
            </button>
          ))}
        </div>

      </main>

      {/* Footer */}
      <footer style={{ borderTop: '1px solid #334155', padding: '24px 0', textAlign: 'center', color: '#64748b', fontSize: '14px', marginTop: '60px' }}>
        © 2026 PhishGuard AI. All rights reserved.
      </footer>

    </div>
  )
}

export default App