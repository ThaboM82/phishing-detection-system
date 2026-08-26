import { useState, FormEvent, ChangeEvent } from 'react';

const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || 'https://phishing-detection-api-dp0h.onrender.com';

export interface Feature {
  id: string;
  title: string;
  icon: string;
  desc: string;
}

export interface PredictionResponse {
  is_phishing?: boolean;
  prediction?: number | string;
  phishing_probability?: number;
  confidence?: number;
  probability?: number;
  [key: string]: unknown;
}

export function App() {
  const [activeTab, setActiveTab] = useState<string>('url');
  const [urlInput, setUrlInput] = useState<string>('');
  const [messageInput, setMessageInput] = useState<string>('');
  const [assistantInput, setAssistantInput] = useState<string>('');
  const [assistantResponse, setAssistantResponse] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<PredictionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (activeTab === 'url' && !urlInput.trim()) return;
    if (activeTab === 'message' && !messageInput.trim()) return;

    const payload = activeTab === 'url' ? { url: urlInput.trim() } : { text: messageInput.trim() };

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(`${API_BASE_URL}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Analysis failed (${response.status}). Check backend service status.`);
      }

      const data: PredictionResponse = await response.json();
      setResult(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Unable to connect to the phishing detection API.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleAssistantAsk = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!assistantInput.trim()) return;

    setAssistantResponse(
      `Security Analysis for "${assistantInput}": Always verify domain extensions, check SSL certificates, and inspect raw mail headers (SPF, DKIM, DMARC) before clicking unknown links.`
    );
  };

  const features: Feature[] = [
    { id: 'url', title: 'URL Scanner', icon: '🔗', desc: 'Instantly check links for malicious intent and phishing red flags.' },
    { id: 'message', title: 'Message Analyzer', icon: '✉️', desc: 'Analyze suspicious emails and SMS messages using heuristic models.' },
    { id: 'file', title: 'File Analyzer', icon: '📁', desc: 'Scan documents and executables securely for potential threat payload.' },
    { id: 'assistant', title: 'AI Chat Assistant', icon: '🤖', desc: 'Ask security advisories about potential phishing techniques.' },
    { id: 'risk', title: 'Risk Scoring', icon: '📊', desc: 'Review detailed threat probability and statistical breakdowns.' },
  ];

  const isPhishing = Boolean(
    result?.is_phishing ?? 
    (result?.prediction === 1) ?? 
    (result?.prediction === 'phishing')
  );

  const rawProb = result?.phishing_probability ?? result?.confidence ?? result?.probability;
  const probability = typeof rawProb === 'number' ? rawProb : undefined;

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 font-sans p-5 box-border">
      <header className="flex justify-between items-center pb-5 border-b border-slate-700 max-w-5xl mx-auto">
        <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => setActiveTab('url')}>
          <span className="text-2xl">🛡️</span>
          <h2 className="text-blue-500 text-2xl font-bold m-0">PhishGuard AI</h2>
        </div>
        <nav className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => setActiveTab('url')}
            className="bg-transparent border-0 text-slate-400 hover:text-slate-200 cursor-pointer text-sm font-medium transition-colors"
          >
            Features
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('url')}
            className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 border-0 rounded-md cursor-pointer font-semibold text-sm transition-colors"
          >
            Get Started
          </button>
        </nav>
      </header>

      <main className="max-w-4xl mx-auto my-10 text-center">
        <div className="mb-10">
          <span className="bg-blue-950 text-blue-400 border border-blue-700 px-3 py-1 rounded-full text-xs uppercase tracking-wider">
            Machine Learning Phishing Protection
          </span>
          <h1 className="text-4xl sm:text-5xl font-extrabold mt-4 mb-3 leading-tight">
            Detect Phishing <br />
            <span className="text-blue-500">Instantly with AI</span>
          </h1>
          <p className="text-slate-400 text-lg max-w-xl mx-auto">
            Protect yourself from web scams using statistical classifiers and rule-based heuristic engines.
          </p>
        </div>

        <div className="bg-slate-800 p-7 rounded-xl border border-slate-700 mb-10 shadow-2xl">
          <h3 className="mt-0 mb-4 text-blue-400 text-lg text-left font-medium">
            Active Tool: {features.find((f) => f.id === activeTab)?.title || 'URL Scanner'}
          </h3>

          {activeTab === 'url' && (
            <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-3">
              <input
                type="url"
                value={urlInput}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setUrlInput(e.target.value)}
                placeholder="Enter URL to check (e.g., https://example.com)..."
                required
                className="flex-1 p-3.5 rounded-lg border border-slate-600 bg-slate-900 text-white text-base focus:outline-none focus:border-blue-500"
              />
              <button
                type="submit"
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-7 py-3.5 border-0 rounded-lg cursor-pointer text-base font-bold transition-colors"
              >
                {loading ? 'Scanning...' : 'Scan Link'}
              </button>
            </form>
          )}

          {activeTab === 'message' && (
            <form onSubmit={handleScan} className="flex flex-col gap-3">
              <textarea
                value={messageInput}
                onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setMessageInput(e.target.value)}
                placeholder="Paste suspicious email body or SMS message text here..."
                rows={4}
                required
                className="w-full p-3.5 rounded-lg border border-slate-600 bg-slate-900 text-white text-sm focus:outline-none focus:border-blue-500 box-border"
              />
              <button
                type="submit"
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-6 py-3 border-0 rounded-lg cursor-pointer text-base font-bold self-end transition-colors"
              >
                {loading ? 'Analyzing...' : 'Analyze Message'}
              </button>
            </form>
          )}

          {activeTab === 'file' && (
            <div className="p-8 border-2 border-dashed border-slate-600 rounded-lg text-slate-400">
              <p className="text-xl mb-2">📁 Drag & drop suspicious files here</p>
              <p className="text-xs text-slate-500">Supported formats: .pdf, .docx, .eml (Max size: 10MB)</p>
            </div>
          )}

          {activeTab === 'assistant' && (
            <form onSubmit={handleAssistantAsk} className="text-left space-y-3">
              <p className="text-slate-400 m-0">🤖 Ask PhishGuard AI Assistant about threat indicators:</p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={assistantInput}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => setAssistantInput(e.target.value)}
                  placeholder="Ask a question (e.g., How do I identify spoofed headers?)..."
                  className="flex-1 p-3 rounded-lg border border-slate-600 bg-slate-900 text-white text-sm focus:outline-none focus:border-blue-500"
                />
                <button
                  type="submit"
                  className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-3 rounded-lg font-semibold text-sm cursor-pointer"
                >
                  Ask
                </button>
              </div>
              {assistantResponse && (
                <div className="mt-3 p-4 bg-slate-900 rounded-lg border border-slate-700 text-slate-300 text-sm">
                  {assistantResponse}
                </div>
              )}
            </form>
          )}

          {activeTab === 'risk' && (
            <div className="text-left text-slate-400">
              <p className="m-0">📊 Enter any URL or message above to generate threat metrics and heuristic breakdowns.</p>
            </div>
          )}
        </div>

        {error && (
          <div className="bg-red-950 text-red-300 p-4 rounded-lg text-left mb-7 border border-red-800">
            ⚠️ <strong>Error:</strong> {error}
          </div>
        )}

        {result && (
          <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 text-left mb-10">
            <h3 className="m-0 mb-4 border-b border-slate-700 pb-3 text-lg font-semibold">
              Analysis Results
            </h3>
            <div className="flex justify-between items-center mb-3">
              <span className="text-slate-400">Verdict:</span>
              <span
                className={`px-3 py-1.5 rounded-md font-bold text-sm border ${
                  isPhishing
                    ? 'bg-red-950 text-red-300 border-red-800'
                    : 'bg-green-950 text-green-300 border-green-800'
                }`}
              >
                {isPhishing ? '🚨 PHISHING DETECTED' : '✅ LEGITIMATE'}
              </span>
            </div>
            {probability !== undefined && (
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Risk Score:</span>
                <span className="font-mono font-bold text-base">
                  {(probability * (probability <= 1 ? 100 : 1)).toFixed(1)}%
                </span>
              </div>
            )}
          </div>
        )}

        <h2 className="text-2xl font-bold mb-2">Powerful Features</h2>
        <p className="text-slate-400 mb-6">Click any card below to open its scanner mode.</p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {features.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setActiveTab(item.id);
                window.scrollTo({ top: 180, behavior: 'smooth' });
              }}
              className={`p-6 rounded-xl text-left cursor-pointer transition-all flex flex-col gap-2 ${
                activeTab === item.id
                  ? 'bg-slate-800 border-2 border-blue-500 shadow-lg'
                  : 'bg-slate-800/80 border border-slate-700 hover:border-slate-600'
              }`}
            >
              <div className="text-3xl">{item.icon}</div>
              <h3 className="m-0 text-lg text-white font-semibold">{item.title}</h3>
              <p className="m-0 text-sm text-slate-400 leading-relaxed">{item.desc}</p>
            </button>
          ))}
        </div>
      </main>

      <footer className="border-t border-slate-800 py-6 text-center text-slate-500 text-sm mt-16">
        © 2026 PhishGuard AI. All rights reserved.
      </footer>
    </div>
  );
}

export default App;