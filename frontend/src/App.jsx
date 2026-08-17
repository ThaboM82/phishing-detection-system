import { useState, useEffect } from 'react';

const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://127.0.0.1:8000'
  : '/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner'); // 'scanner' | 'analytics'

  // Scanner State
  const [url, setUrl] = useState('');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  // Analytics State
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const [verdictFilter, setVerdictFilter] = useState('');

  // Fetch telemetry data whenever Analytics tab or filter changes
  useEffect(() => {
    if (activeTab === 'analytics') {
      fetchAnalyticsData();
    }
  }, [activeTab, verdictFilter]);

  const fetchAnalyticsData = async () => {
    setAnalyticsLoading(true);
    try {
      // 1. Fetch aggregate metrics
      const statsRes = await fetch(`${API_BASE}/api/v1/telemetry/stats`);
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      // 2. Fetch raw audit scan logs with optional verdict filter
      const filterQuery = verdictFilter ? `?verdict_filter=${verdictFilter}` : '';
      const logsRes = await fetch(`${API_BASE}/api/v1/telemetry${filterQuery}`);
      if (logsRes.ok) {
        const logsData = await logsRes.json();
        setLogs(logsData);
      }
    } catch (err) {
      console.error("Failed to fetch analytics telemetry:", err);
    } finally {
      setAnalyticsLoading(false);
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setScanLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      });
      if (!res.ok) throw new Error('Inspection request failed.');
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      alert(`Error: ${err.message}`);
    } finally {
      setScanLoading(false);
    }
  };

  const getVerdictBadge = (verdict) => {
    switch (verdict) {
      case 'BENIGN':
      case 'LEGITIMATE':
        return <span className="bg-emerald-950/80 border border-emerald-600 text-emerald-400 text-xs px-2.5 py-1 rounded-full font-semibold">BENIGN</span>;
      case 'SUSPICIOUS':
        return <span className="bg-amber-950/80 border border-amber-600 text-amber-400 text-xs px-2.5 py-1 rounded-full font-semibold">SUSPICIOUS</span>;
      default:
        return <span className="bg-rose-950/80 border border-rose-600 text-rose-400 text-xs px-2.5 py-1 rounded-full font-semibold">PHISHING</span>;
    }
  };

  const getVerdictStyle = (verdict) => {
    switch (verdict) {
      case 'BENIGN':
      case 'LEGITIMATE':
        return 'bg-emerald-950/40 border-emerald-600 text-emerald-400';
      case 'SUSPICIOUS':
        return 'bg-amber-950/40 border-amber-600 text-amber-400';
      default:
        return 'bg-rose-950/40 border-rose-600 text-rose-400';
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 font-sans flex flex-col">
      {/* Header & Navigation */}
      <nav className="border-b border-slate-800 bg-slate-950 px-6 py-4">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-indigo-400">🛡️ Phishing Detector</h1>
            <span className="text-xs border border-slate-700 px-3 py-0.5 rounded-full text-slate-400">
              v1.1.0
            </span>
          </div>

          {/* Navigation Tabs */}
          <div className="flex bg-slate-900 border border-slate-800 p-1 rounded-lg">
            <button
              onClick={() => setActiveTab('scanner')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'scanner'
                  ? 'bg-indigo-600 text-white shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Scanner
            </button>
            <button
              onClick={() => setActiveTab('analytics')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'analytics'
                  ? 'bg-indigo-600 text-white shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Analytics & Telemetry
            </button>
          </div>
        </div>
      </nav>

      {/* Main Container */}
      <main className="flex-1 max-w-6xl mx-auto w-full p-6">
        {/* TAB 1: SCANNER */}
        {activeTab === 'scanner' && (
          <div className="max-w-4xl mx-auto">
            <form onSubmit={handleScan} className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl mb-8">
              <label className="block text-sm font-medium mb-2 text-slate-300">Target URL</label>
              <div className="flex gap-3">
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example-phishing-site.com"
                  className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-slate-100 focus:outline-none focus:border-indigo-500"
                  required
                />
                <button
                  type="submit"
                  disabled={scanLoading}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-6 py-3 rounded-lg transition-colors disabled:opacity-50"
                >
                  {scanLoading ? 'Analyzing...' : 'Scan URL'}
                </button>
              </div>
            </form>

            {scanResult && (
              <div className="space-y-6">
                <div className={`p-6 rounded-xl border flex justify-between items-center ${getVerdictStyle(scanResult.verdict)}`}>
                  <div>
                    <span className="text-xs uppercase tracking-wider text-slate-400">Verdict</span>
                    <h2 className="text-3xl font-extrabold mt-1">{scanResult.verdict}</h2>
                  </div>
                  <div className="text-right">
                    <span className="text-xs uppercase tracking-wider text-slate-400">Risk Score</span>
                    <div className="text-3xl font-bold mt-1">
                      {Math.round((scanResult.risk_score ?? scanResult.ml_probability ?? 0) * 100)}%
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-slate-800 border border-slate-700 p-5 rounded-xl">
                    <h3 className="text-sm font-semibold text-slate-400 mb-1">ML Probability</h3>
                    <p className="text-2xl font-bold">{Math.round((scanResult.ml_probability || 0) * 100)}% Phishing</p>
                  </div>
                  <div className="bg-slate-800 border border-slate-700 p-5 rounded-xl">
                    <h3 className="text-sm font-semibold text-slate-400 mb-1">Flags Triggered</h3>
                    <p className="text-2xl font-bold">{scanResult.heuristic_flags_count ?? scanResult.flags_count ?? 0}</p>
                  </div>
                </div>

                <div className="bg-slate-800 border border-slate-700 p-5 rounded-xl">
                  <h3 className="text-sm font-semibold text-slate-400 mb-3">Triggered Heuristic Rules</h3>
                  {scanResult.fired_rules && scanResult.fired_rules.length > 0 ? (
                    <ul className="space-y-2 text-sm">
                      {scanResult.fired_rules.map((rule, idx) => {
                        const name = typeof rule === 'string' ? rule : (rule.rule_name || rule.rule || 'Flagged Rule');
                        const desc = typeof rule === 'object' ? rule.description : '';
                        return (
                          <li key={idx} className="bg-slate-900 px-3 py-2 rounded border border-slate-700 flex justify-between items-center">
                            <span className="text-rose-300 font-medium">{name}</span>
                            {desc && <span className="text-slate-400 text-xs">{desc}</span>}
                          </li>
                        );
                      })}
                    </ul>
                  ) : (
                    <p className="text-slate-500 italic text-sm">No suspicious heuristic rules triggered.</p>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: ANALYTICS & TELEMETRY */}
        {activeTab === 'analytics' && (
          <div className="space-y-8">
            {/* Metric Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-slate-800 border border-slate-700 p-5 rounded-xl shadow-lg">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Scans</span>
                <p className="text-3xl font-extrabold text-white mt-2">{stats ? stats.total_scans : 0}</p>
              </div>

              <div className="bg-slate-800 border border-slate-700 p-5 rounded-xl shadow-lg">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Phishing Detected</span>
                <p className="text-3xl font-extrabold text-rose-400 mt-2">{stats ? stats.phishing_count : 0}</p>
              </div>

              <div className="bg-slate-800 border border-slate-700 p-5 rounded-xl shadow-lg">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Phishing Ratio</span>
                <p className="text-3xl font-extrabold text-amber-400 mt-2">
                  {stats ? `${stats.phishing_ratio_percentage}%` : '0%'}
                </p>
              </div>

              <div className="bg-slate-800 border border-slate-700 p-5 rounded-xl shadow-lg">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Avg ML Probability</span>
                <p className="text-3xl font-extrabold text-indigo-400 mt-2">
                  {stats ? `${Math.round(stats.avg_ml_probability * 100)}%` : '0%'}
                </p>
              </div>
            </div>

            {/* Scan History Audit Log Table */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl shadow-xl overflow-hidden">
              <div className="p-5 border-b border-slate-700 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                  <h3 className="text-lg font-bold text-slate-100">Scan Audit History</h3>
                  <p className="text-xs text-slate-400 mt-0.5">Real-time telemetry and inspection logs</p>
                </div>

                <div className="flex items-center gap-3">
                  <select
                    value={verdictFilter}
                    onChange={(e) => setVerdictFilter(e.target.value)}
                    className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="">All Verdicts</option>
                    <option value="PHISHING">PHISHING</option>
                    <option value="SUSPICIOUS">SUSPICIOUS</option>
                    <option value="BENIGN">BENIGN / LEGITIMATE</option>
                  </select>

                  <button
                    onClick={fetchAnalyticsData}
                    className="bg-slate-700 hover:bg-slate-600 text-xs px-3 py-2 rounded-lg transition-colors"
                  >
                    Refresh
                  </button>
                </div>
              </div>

              {analyticsLoading ? (
                <div className="p-12 text-center text-slate-400">Loading telemetry history...</div>
              ) : logs.length === 0 ? (
                <div className="p-12 text-center text-slate-500">No scan history recorded yet.</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm text-slate-300">
                    <thead className="bg-slate-900/60 text-xs uppercase text-slate-400 border-b border-slate-700">
                      <tr>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4">Target URL</th>
                        <th className="py-3 px-4">Verdict</th>
                        <th className="py-3 px-4 text-center">ML Prob</th>
                        <th className="py-3 px-4 text-center">Flags</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/50">
                      {logs.map((log) => (
                        <tr key={log.id} className="hover:bg-slate-750/50 transition-colors">
                          <td className="py-3 px-4 text-xs text-slate-400 whitespace-nowrap">
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 font-mono text-xs max-w-xs truncate text-indigo-300" title={log.url}>
                            {log.url}
                          </td>
                          <td className="py-3 px-4">{getVerdictBadge(log.verdict)}</td>
                          <td className="py-3 px-4 text-center font-semibold">
                            {Math.round((log.ml_probability || 0) * 100)}%
                          </td>
                          <td className="py-3 px-4 text-center font-bold text-amber-400">
                            {log.heuristic_flags_count || 0}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}