import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [showFeatures, setShowFeatures] = useState(false);
  const [history, setHistory] = useState([]);

  // Load history from localStorage on initial render
  useEffect(() => {
    const saved = localStorage.getItem('phishing_scan_history');
    if (saved) {
      try {
        setHistory(JSON.parse(saved));
      } catch (e) {
        console.error('Failed to parse scan history');
      }
    }
  }, []);

  // Save history updates to localStorage
  const updateHistory = (newResult) => {
    setHistory((prev) => {
      // Remove duplicate if already scanned recently
      const filtered = prev.filter((item) => item.url !== newResult.url);
      const updated = [newResult, ...filtered].slice(0, 10); // Keep last 10 scans
      localStorage.setItem('phishing_scan_history', JSON.stringify(updated));
      return updated;
    });
  };

  const handleAnalyze = async (e, customUrl = null) => {
    if (e) e.preventDefault();
    const targetUrl = customUrl || url;
    if (!targetUrl.trim()) return;

    if (customUrl) setUrl(customUrl);

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post('http://127.0.0.1:8000/analyze', {
        url: targetUrl.trim(),
      });
      setResult(response.data);
      updateHistory(response.data);
    } catch (err) {
      if (err.response) {
        setError(`API Error (${err.response.status}): ${err.response.data.detail || 'Inspection failed'}`);
      } else {
        setError('Could not connect to FastAPI server. Ensure uvicorn is running on port 8000.');
      }
    } finally {
      setLoading(false);
    }
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem('phishing_scan_history');
  };

  const getVerdictStyle = (verdict) => {
    switch (verdict) {
      case 'BLOCKED':
        return { bg: '#fee2e2', border: '#ef4444', text: '#991b1b', badge: '?? BLOCKED' };
      case 'SUSPICIOUS':
        return { bg: '#fef3c7', border: '#f59e0b', text: '#92400e', badge: '?? SUSPICIOUS' };
      case 'BENIGN':
        return { bg: '#dcfce7', border: '#22c55e', text: '#166534', badge: '? BENIGN' };
      default:
        return { bg: '#f3f4f6', border: '#9ca3af', text: '#374151', badge: verdict };
    }
  };

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1 style={styles.title}>??? Phishing URL Detector</h1>
        <p style={styles.subtitle}>Real-time heuristic & machine learning analysis</p>
      </header>

      <form onSubmit={(e) => handleAnalyze(e)} style={styles.form}>
        <input
          type="text"
          placeholder="https://example-phishing-link.com/login"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={styles.input}
        />
        <button type="submit" disabled={loading} style={styles.button}>
          {loading ? 'Analyzing...' : 'Analyze URL'}
        </button>
      </form>

      {error && <div style={styles.errorBox}>{error}</div>}

      {result && (
        <div style={styles.resultsContainer}>
          {/* Verdict Banner */}
          {(() => {
            const style = getVerdictStyle(result.verdict);
            return (
              <div style={{ ...styles.verdictCard, backgroundColor: style.bg, borderColor: style.border, color: style.text }}>
                <h2 style={{ margin: 0 }}>{style.badge}</h2>
                <p style={{ margin: '8px 0 0 0', fontWeight: 'bold', wordBreak: 'break-all' }}>{result.url}</p>
              </div>
            );
          })()}

          {/* Metrics Summary */}
          <div style={styles.metricsGrid}>
            <div style={styles.metricCard}>
              <span style={styles.metricLabel}>Risk Probability</span>
              <span style={styles.metricValue}>{(result.ml_probability * 100).toFixed(1)}%</span>
            </div>
            <div style={styles.metricCard}>
              <span style={styles.metricLabel}>Rules Triggered</span>
              <span style={styles.metricValue}>{result.heuristic_flags_count}</span>
            </div>
            <div style={styles.metricCard}>
              <span style={styles.metricLabel}>Phishing Verdict</span>
              <span style={styles.metricValue}>{result.is_phishing ? 'YES' : 'NO'}</span>
            </div>
          </div>

          {/* Triggered Rules */}
          <div style={styles.section}>
            <h3>?? Triggered Heuristic Rules</h3>
            {result.fired_rules && result.fired_rules.length > 0 ? (
              <ul style={styles.rulesList}>
                {result.fired_rules.map((rule, idx) => (
                  <li key={idx} style={styles.ruleItem}>
                    <strong>{rule.rule}</strong>: {rule.reason}
                  </li>
                ))}
              </ul>
            ) : (
              <p style={{ color: '#6b7280' }}>No heuristic rules were triggered.</p>
            )}
          </div>

          {/* Features Toggle */}
          <div style={styles.section}>
            <button onClick={() => setShowFeatures(!showFeatures)} style={styles.toggleButton}>
              {showFeatures ? 'Hide Extracted Features ?' : 'Show Extracted Features ?'}
            </button>
            {showFeatures && (
              <pre style={styles.jsonBox}>
                {JSON.stringify(result.extracted_features, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}

      {/* History Log Section */}
      {history.length > 0 && (
        <div style={{ ...styles.section, marginTop: '30px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h3 style={{ margin: 0 }}>?? Recent Scans</h3>
            <button onClick={clearHistory} style={{ ...styles.toggleButton, color: '#ef4444' }}>
              Clear History
            </button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {history.map((item, index) => {
              const style = getVerdictStyle(item.verdict);
              return (
                <div
                  key={index}
                  onClick={() => handleAnalyze(null, item.url)}
                  style={styles.historyItem}
                >
                  <span style={{ fontSize: '0.85rem', fontWeight: 'bold', color: style.text, padding: '2px 8px', borderRadius: '4px', backgroundColor: style.bg }}>
                    {item.verdict}
                  </span>
                  <span style={{ flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontSize: '0.9rem' }}>
                    {item.url}
                  </span>
                  <span style={{ fontSize: '0.8rem', color: '#6b7280' }}>Re-scan ?</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

const styles = {
  container: { maxWidth: '750px', margin: '40px auto', fontFamily: 'system-ui, sans-serif', padding: '0 20px' },
  header: { textAlign: 'center', marginBottom: '30px' },
  title: { margin: 0, fontSize: '2rem', color: '#111827' },
  subtitle: { margin: '8px 0 0 0', color: '#6b7280' },
  form: { display: 'flex', gap: '10px', marginBottom: '20px' },
  input: { flex: 1, padding: '12px 16px', fontSize: '1rem', borderRadius: '8px', border: '1px solid #d1d5db' },
  button: { padding: '12px 24px', fontSize: '1rem', fontWeight: 'bold', backgroundColor: '#2563eb', color: '#fff', border: 'none', borderRadius: '8px', cursor: 'pointer' },
  errorBox: { padding: '12px', backgroundColor: '#fee2e2', color: '#991b1b', borderRadius: '8px', marginBottom: '20px' },
  resultsContainer: { display: 'flex', flexDirection: 'column', gap: '20px' },
  verdictCard: { padding: '20px', borderRadius: '8px', borderLeft: '6px solid' },
  metricsGrid: { display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '15px' },
  metricCard: { padding: '15px', backgroundColor: '#f9fafb', borderRadius: '8px', border: '1px solid #e5e7eb', textAlign: 'center', display: 'flex', flexDirection: 'column' },
  metricLabel: { fontSize: '0.85rem', color: '#6b7280' },
  metricValue: { fontSize: '1.5rem', fontWeight: 'bold', color: '#111827', marginTop: '4px' },
  section: { backgroundColor: '#ffffff', border: '1px solid #e5e7eb', padding: '20px', borderRadius: '8px' },
  rulesList: { paddingLeft: '20px', margin: 0 },
  ruleItem: { marginBottom: '8px' },
  toggleButton: { background: 'none', border: 'none', color: '#2563eb', cursor: 'pointer', fontWeight: 'bold', padding: 0 },
  jsonBox: { backgroundColor: '#1f2937', color: '#f3f4f6', padding: '15px', borderRadius: '8px', marginTop: '10px', overflowX: 'auto', fontSize: '0.85rem' },
  historyItem: { display: 'flex', alignItems: 'center', gap: '12px', padding: '10px 14px', borderRadius: '6px', border: '1px solid #f3f4f6', cursor: 'pointer', backgroundColor: '#f9fafb', transition: 'background-color 0.2s' },
};

export default App;
