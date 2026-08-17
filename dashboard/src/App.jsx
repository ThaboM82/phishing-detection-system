import { useState } from 'react'

function App() {
  const [activeTab, setActiveTab] = useState('url') // 'url' | 'message' | 'file' | 'assistant'
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

      if (!response.ok) throw new Error('Analysis failed. Please check backend service status.')

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err.message || 'Error connecting to API.')
    } finally {
      setLoading(false)
    }
  }

  const features = [
    { id: 'url', title: 'URL Scanner', icon: '🔗', desc: 'Instantly check links for malicious intent and heuristic flags.' },
    { id: 'message', title: 'Message Analyzer', icon: '✉️', desc: 'Analyze suspicious emails and SMS content using NLP models.' },
    { id: 'file', title: 'File Analyzer', icon: '📁', desc: 'Scan document structures and executables for threat markers.' },
    { id: 'assistant', title: 'AI Assistant', icon: '🤖', desc: 'Query our security assistant regarding ongoing cyber threats.' },
  ]

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0f172a', color: '#ffffff', fontFamily: 'system-ui, sans-serif', padding: '20px', boxSizing: 'border-box' }}>
      
      {/* Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '20px', borderBottom: '1px solid #334155', maxWidth: '1000px', margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }} onClick={() => setActiveTab('url')}>
          <span style={{ fontSize: '1.5rem' }}>🛡️</span>
          <h2 style={{ color: '#3b82f6', margin: 0, fontSize: '1.5rem', fontWeight: 'bold' }}>PhishGuard AI</h2>
        </div>
        <nav style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
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

      {/* Main Container */}
      <main style={{ maxWidth: '900px', margin: '40px auto', textAlign: 'center' }}>
        
        {/* Hero Section */}
        <div style={{ marginBottom: '40px' }}>
          <span style={{ backgroundColor: '#1e3a8a', color: '#60a5fa', border: '1px solid #1d4ed8', padding: '4px 12px', borderRadius: '20px', fontSize: '12px', textTransform: 'uppercase', tracking: '1px' }}>
            New: ML Powered Threat Detection
          </span>
          <h1 style={{ fontSize: '2.75rem', fontWeight: '800', marginTop: '16px', marginBottom: '12px', lineHeight: '1.2' }}>
            Detect Cyber Threats <br />
            <span style={{ color: '#3b82f6' }}>Instantly with AI</span>
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '1.1rem', maxWidth: '600px', margin: '0 auto' }}>
            Protect yourself from phishing and scams using custom hybrid ML models and automated heuristics.
          </p>
        </div>

        {/* Tab Navigation Controls */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginBottom: '24px', flexWrap: 'wrap' }}>
          {features.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => { setActiveTab(item.id); setResult(null); setError(null); }}
              style={{
                padding: '10px 18px',
                borderRadius: '8px',
                border: activeTab === item.id ? '1px solid #3b82f6' : '1px solid #334155',
                backgroundColor: activeTab === item.id ? '#1e293b' : 'transparent',
                color: activeTab === item.id ? '#60a5fa' : '#94a3b8',
                cursor: 'pointer',
                fontWeight: '600',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                transition: 'all 0.2s ease'
              }}
            >
              <span>{item.icon}</span>
              <span>{item.title}</span>
            </button>
          ))}
        </div>

        {/* Dynamic Interactive Input Form */}
        <div style={{ backgroundColor: '#1e293b', padding: '28px', borderRadius: '12px', border: '1px solid #334155', marginBottom: '40px', boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.3)' }}>
          {activeTab === 'url' && (
            <form onSubmit={handleScan} style={{ display: 'flex', gap: '12px', flexDirection: 'column' }}>
              <div style={{ display: 'flex', gap: '12px' }}>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="Paste URL to analyze (e.g., https://suspicious-domain.com)..."
                  required
                  style={{ flex: '1', padding: '14px 18px', borderRadius: '8px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#ffffff', fontSize: '16px', outline: 'none' }}
                />
                <button
                  type="submit"
                  disabled={loading}
                  style={{ backgroundColor: '#2563eb', color: '#ffffff', padding: '14px 28px', border: 'none', borderRadius: '8px', cursor: 'pointer', fontSize: '16px', fontWeight: 'bold', minWidth: '130px' }}
                >
                  {loading ? 'Scanning...' : 'Scan Link'}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'message' && (
            <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <textarea
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Paste suspicious email or SMS text here..."
                rows={4}
                required
                style={{ width: '100%', padding: '14px 18px', borderRadius: '8px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#ffffff', fontSize: '15px', outline: 'none', resize: 'vertical', boxSizing: 'border-box' }}
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
              <p style={{ margin: '0 0 12px 0' }}>🤖 Ask PhishGuard Assistant about security advisories or URL threats:</p>
              <input
                type="text"
                placeholder="How can I detect spoofed email headers?"
                style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#ffffff', fontSize: '15px', boxSizing: 'border-box' }}
              />
            </div>
          )}
        </div>

        {/* Error Feedback Display */}
        {error && (
          <div style={{ backgroundColor: '#7f1d1d', color: '#fca5a5', padding: '16px', borderRadius: '8px', textAlign: 'left', marginBottom: '30px', border: '1px solid #991b1b' }}>
            ⚠️ <strong>Error:</strong> {error}
          </div>
        )}

        {/* Live Analysis Output Box */}
        {result && (
          <div style={{ backgroundColor: '#1e293b', padding: '24px', borderRadius: '12px', border: '1px solid #334155', textAlign: 'left', marginBottom: '40px' }}>
            <h3 style={{ margin: '0 0 16px 0', borderBottom: '1px solid #334155', paddingBottom: '12px', fontSize: '1.2rem' }}>
              Scan Results Summary
            </h3>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span style={{ color: '#94a3b8' }}>Threat Verdict:</span>
              <span style={{
                padding: '6px 14px',
                borderRadius: '6px',
                fontWeight: 'bold',
                fontSize: '14px',
                backgroundColor: result.is_phishing ? '#7f1d1d' : '#14532d',
                color: result.is_phishing ? '#fca5a5' : '#86efac',
                border: result.is_phishing ? '1px solid #991b1b' : '1px solid #166534'
              }}>
                {result.is_phishing ? '🚨 PHISHING THREAT DETECTED' : '✅ LEGITIMATE / SAFE'}
              </span>
            </div>
            
            {result.phishing_probability !== undefined && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ color: '#94a3b8' }}>Confidence Risk Score:</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 'bold', fontSize: '16px' }}>
                  {(result.phishing_probability * 100).toFixed(1)}%
                </span>
              </div>
            )}

            {result.heuristic_triggers && (
              <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px dashed #334155' }}>
                <p style={{ color: '#94a3b8', fontSize: '14px', margin: '0 0 8px 0' }}>Triggered Heuristics:</p>
                <ul style={{ margin: 0, paddingLeft: '20px', color: '#cbd5e1', fontSize: '14px' }}>
                  {result.heuristic_triggers.map((rule, idx) => (
                    <li key={idx} style={{ marginBottom: '4px' }}>{rule}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* Feature Grid with Interactive Clicks */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginTop: '40px' }}>
          {features.map((item) => (
            <div
              key={item.id}
              onClick={() => { setActiveTab(item.id); window.scrollTo({ top: 200, behavior: 'smooth' }); }}
              style={{
                backgroundColor: '#1e293b',
                padding: '20px',
                borderRadius: '10px',
                border: activeTab === item.id ? '1px solid #3b82f6' : '1px solid #334155',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'transform 0.2s ease, border-color 0.2s ease',
              }}
              onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-3px)'}
              onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0px)'}
            >
              <div style={{ fontSize: '1.8rem', marginBottom: '10px' }}>{item.icon}</div>
              <h3 style={{ margin: '0 0 8px 0', fontSize: '1.1rem', color: '#ffffff' }}>{item.title}</h3>
              <p style={{ margin: 0, fontSize: '0.875rem', color: '#94a3b8', lineHeight: '1.4' }}>{item.desc}</p>
            </div>
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