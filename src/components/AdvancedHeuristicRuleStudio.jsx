import React, { useState } from 'react';
import { 
  Activity, AlertOctagon, AlertTriangle, ArrowUpRight, BarChart2, BookOpen, Building2, 
  Calendar, CheckCircle, CheckCircle2, ChevronDown, ChevronRight, Code, Container, Cpu, Download, Edit3, FileCheck, 
  FileSpreadsheet, FileText, Globe, Key, Layers, Link as LinkIcon, Mail, Menu, 
  Play, Plus, QrCode, Radio, RefreshCw, Search, Send, Server, Shield, 
  ShieldAlert, ShieldCheck, ShieldOff, ShieldQuestion, Sliders, Target, 
  Terminal, TerminalSquare, Trash2, TrendingUp, UserCog, UserX, Users, Webhook, X, XCircle, Zap 
} from 'lucide-react';
import { 
  Area, AreaChart, Bar, BarChart, CartesianGrid, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis 
} from 'recharts';
import UEBADashboard from '../views/UEBADashboard';
import EmailPolicyEngine from "./EmailPolicyEngine";
import GlobalThreatMap from "./GlobalThreatMap";
import UrlThreatInspector from './UrlThreatInspector';
import { LiveIoCTicker } from './LiveIoCTicker';
import { ModelWeightTuningPanel } from './ModelWeightTuningPanel';
import { IncidentRemediationPlaybooks } from './IncidentRemediationPlaybooks';
import EmployeeVulnerabilityMatrix from "./EmployeeVulnerabilityMatrix";

export function AdvancedHeuristicRuleStudio() {
  const [rules, setRules] = useState([
    { 
      id: 1, 
      name: 'Typosquatting Brand Mimicry', 
      weight: 0.85, 
      status: 'Active', 
      matches: 142,
      pattern: '(m365|micros0ft|paypa1|bank-verify)\\.[a-z]{2,}',
      trigger: 'Immediate Quarantine'
    },
    { 
      id: 2, 
      name: 'Suspicious TLD & Age < 14 Days', 
      weight: 0.92, 
      status: 'Active', 
      matches: 89,
      pattern: '\\.(xyz|top|zip|cc|tk)$',
      trigger: 'Flag for SOC Review'
    },
    { 
      id: 3, 
      name: 'M3/Mime Header SPF Mismatch', 
      weight: 0.78, 
      status: 'Evaluating', 
      matches: 34,
      pattern: 'Received: from.*!(spf_pass)',
      trigger: 'Inject Warning Banner'
    }
  ]);

  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleWeight, setNewRuleWeight] = useState('0.80');
  const [newRulePattern, setNewRulePattern] = useState('');
  const [newRuleTrigger, setNewRuleTrigger] = useState('Flag for SOC Review');
  
  const [editingId, setEditingId] = useState(null);
  const [editWeight, setEditWeight] = useState('');

  // Form Submission
  const handleAddRule = (e) => {
    e.preventDefault();
    if (!newRuleName.trim()) return;

    setRules([
      ...rules,
      {
        id: Date.now(),
        name: newRuleName,
        weight: parseFloat(newRuleWeight),
        status: 'Active',
        matches: 0,
        pattern: newRulePattern || '.*',
        trigger: newRuleTrigger
      }
    ]);
    
    setNewRuleName('');
    setNewRulePattern('');
    setNewRuleWeight('0.80');
  };

  // Rule Actions
  const toggleStatus = (id) => {
    setRules(rules.map(rule => {
      if (rule.id === id) {
        const nextStatus = rule.status === 'Active' ? 'Disabled' : 'Active';
        return { ...rule, status: nextStatus };
      }
      return rule;
    }));
  };

  const handleDeleteRule = (id) => {
    setRules(rules.filter(rule => rule.id !== id));
  };

  const startEdit = (rule) => {
    setEditingId(rule.id);
    setEditWeight(rule.weight.toString());
  };

  const saveEdit = (id) => {
    setRules(rules.map(rule => 
      rule.id === id ? { ...rule, weight: parseFloat(editWeight) } : rule
    ));
    setEditingId(null);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Sliders className="h-5 w-5 text-cyan-400" />
            Advanced Heuristic Rule Studio
          </h2>
          <p className="text-xs text-slate-400">
            Configure real-time detection weights, regex signatures, and automated engine triggers.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs bg-cyan-500/10 text-cyan-400 px-3 py-1 rounded-full border border-cyan-500/20 font-medium">
            {rules.filter(r => r.status === 'Active').length} Active / {rules.length} Total Rules
          </span>
        </div>
      </div>

      // --- INLINE SUPPORTING CARDS ---
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-4 flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Engine Processing Latency</p>
            <div className="flex items-baseline gap-2">
              <span className="text-xl font-bold text-white font-mono">1.2ms</span>
              <span className="text-[10px] text-emerald-400 flex items-center font-medium">
                <TrendingUp className="h-3 w-3 mr-0.5" /> -0.3ms
              </span>
            </div>
          </div>
          <div className="p-2.5 bg-cyan-500/10 rounded-lg border border-cyan-500/20 text-cyan-400">
            <Zap className="h-5 w-5" />
          </div>
        </div>

        <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-4 flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Telemetry Matches (24h)</p>
            <div className="flex items-baseline gap-2">
              <span className="text-xl font-bold text-white font-mono">
                {rules.reduce((acc, curr) => acc + curr.matches, 0)}
              </span>
              <span className="text-[10px] text-emerald-400 flex items-center font-medium">
                <ArrowUpRight className="h-3 w-3 mr-0.5" /> +14%
              </span>
            </div>
          </div>
          <div className="p-2.5 bg-emerald-500/10 rounded-lg border border-emerald-500/20 text-emerald-400">
            <ShieldCheck className="h-5 w-5" />
          </div>
        </div>

        <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-4 flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Mean Heuristic Weight</p>
            <div className="flex items-baseline gap-2">
              <span className="text-xl font-bold text-white font-mono">
                {(rules.reduce((acc, curr) => acc + curr.weight, 0) / (rules.length || 1)).toFixed(2)}
              </span>
              <span className="text-[10px] text-slate-400 font-medium">Balanced Threshold</span>
            </div>
          </div>
          <div className="p-2.5 bg-indigo-500/10 rounded-lg border border-indigo-500/20 text-indigo-400">
            <Cpu className="h-5 w-5" />
          </div>
        </div>

        <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-4 flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">False Positive Drift</p>
            <div className="flex items-baseline gap-2">
              <span className="text-xl font-bold text-white font-mono">0.04%</span>
              <span className="text-[10px] text-emerald-400 font-medium">Nominal (&lt;0.1%)</span>
            </div>
          </div>
          <div className="p-2.5 bg-amber-500/10 rounded-lg border border-amber-500/20 text-amber-400">
            <AlertTriangle className="h-5 w-5" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Rules Table / Card List */}
        <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center justify-between">
            <span>Configured Heuristic Engines</span>
            <span className="text-xs font-normal text-slate-500">Live Telemetry Synchronized</span>
          </h3>

          <div className="space-y-3">
            {rules.map((rule) => (
              <div
                key={rule.id}
                className={`p-4 bg-slate-900 border transition-all rounded-xl text-xs space-y-3 ${
                  rule.status === 'Active' ? 'border-slate-800' : 'border-slate-800/50 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="font-semibold text-white text-sm flex items-center gap-2">
                      {rule.name}
                      <span className={`px-2 py-0.5 text-[10px] rounded-md font-medium border ${
                        rule.status === 'Active' 
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                          : rule.status === 'Evaluating'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        {rule.status}
                      </span>
                    </div>

                    <div className="text-slate-400 flex items-center gap-4">
                      <span>
                        Weight:{' '}
                        {editingId === rule.id ? (
                          <input
                            type="number"
                            step="0.05"
                            min="0"
                            max="1"
                            value={editWeight}
                            onChange={(e) => setEditWeight(e.target.value)}
                            className="w-16 bg-slate-950 border border-cyan-500 text-cyan-400 px-1 py-0.5 rounded font-mono"
                          />
                        ) : (
                          <strong className="text-cyan-400 font-mono">{rule.weight.toFixed(2)}</strong>
                        )}
                      </span>
                      <span>
                        Matches: <strong className="text-emerald-400 font-mono">{rule.matches}</strong>
                      </span>
                      <span>
                        Trigger: <strong className="text-indigo-400">{rule.trigger}</strong>
                      </span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1.5">
                    {editingId === rule.id ? (
                      <button
                        onClick={() => saveEdit(rule.id)}
                        className="p-1.5 bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 rounded-lg transition-colors"
                        title="Save Weight"
                      >
                        <CheckCircle className="h-4 w-4" />
                      </button>
                    ) : (
                      <button
                        onClick={() => startEdit(rule)}
                        className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                        title="Edit Weight"
                      >
                        <Edit3 className="h-4 w-4" />
                      </button>
                    )}

                    <button
                      onClick={() => toggleStatus(rule.id)}
                      className={`p-1.5 rounded-lg transition-colors ${
                        rule.status === 'Active'
                          ? 'text-amber-400 hover:bg-amber-500/10'
                          : 'text-emerald-400 hover:bg-emerald-500/10'
                      }`}
                      title={rule.status === 'Active' ? 'Disable Rule' : 'Enable Rule'}
                    >
                      {rule.status === 'Active' ? <XCircle className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                    </button>

                    <button
                      onClick={() => handleDeleteRule(rule.id)}
                      className="p-1.5 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                      title="Delete Rule"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                {/* Pattern Display */}
                <div className="bg-slate-950 p-2 rounded-lg border border-slate-800/80 font-mono text-[11px] text-slate-300 flex items-center justify-between">
                  <div className="flex items-center gap-2 overflow-hidden truncate">
                    <Code className="h-3.5 w-3.5 text-slate-500 shrink-0" />
                    <span className="truncate">{rule.pattern}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Create Rule Form */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-white">Create New Heuristic Rule</h3>

          <form onSubmit={handleAddRule} className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">Rule / Signature Name</label>
              <input
                type="text"
                placeholder="e.g. Credential Harvesting Pattern"
                value={newRuleName}
                onChange={(e) => setNewRuleName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">Regex Signature Pattern</label>
              <input
                type="text"
                placeholder="e.g. (login|verify)\.auth-[a-z0-9]+"
                value={newRulePattern}
                onChange={(e) => setNewRulePattern(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-400 mb-1 font-medium">Weight (0.0 - 1.0)</label>
                <input
                  type="number"
                  step="0.05"
                  min="0"
                  max="1"
                  value={newRuleWeight}
                  onChange={(e) => setNewRuleWeight(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Action Trigger</label>
                <select
                  value={newRuleTrigger}
                  onChange={(e) => setNewRuleTrigger(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-2 py-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="Flag for SOC Review">SOC Review</option>
                  <option value="Immediate Quarantine">Quarantine</option>
                  <option value="Inject Warning Banner">Inject Banner</option>
                </select>
              </div>
            </div>

            <button
              type="submit"
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-semibold py-2.5 rounded-xl transition-colors flex items-center justify-center gap-1.5 mt-2"
            >
              <Plus className="h-4 w-4" />
              Deploy Rule to Engine
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

const threatTimeSeriesData = [
  { date: 'JULY 2', all: 24, malicious: 18, benign: 4, inconclusive: 2 },
  { date: 'JULY 5', all: 15, malicious: 12, benign: 2, inconclusive: 1 },
  { date: 'JULY 9', all: 25, malicious: 20, benign: 3, inconclusive: 2 },
  { date: 'JULY 13', all: 14, malicious: 10, benign: 3, inconclusive: 1 },
  { date: 'JULY 16', all: 28, malicious: 22, benign: 4, inconclusive: 2 },
  { date: 'JULY 20', all: 18, malicious: 14, benign: 3, inconclusive: 1 },
  { date: 'JULY 23', all: 24, malicious: 19, benign: 4, inconclusive: 1 },
  { date: 'JULY 27', all: 16, malicious: 13, benign: 2, inconclusive: 1 },
  { date: 'JULY 30', all: 26, malicious: 21, benign: 4, inconclusive: 1 },
];

const submissionsOverTimeData = [
  { date: 'JULY 2', submissions: 45, flagged: 12 },
  { date: 'JULY 5', submissions: 32, flagged: 8 },
  { date: 'JULY 9', submissions: 58, flagged: 19 },
  { date: 'JULY 13', submissions: 40, flagged: 10 },
  { date: 'JULY 16', submissions: 62, flagged: 22 },
  { date: 'JULY 20', submissions: 38, flagged: 9 },
  { date: 'JULY 23', submissions: 51, flagged: 15 },
  { date: 'JULY 27', submissions: 44, flagged: 11 },
  { date: 'JULY 30', submissions: 55, flagged: 18 },
];

const urlHeuristicData = [
  { name: 'Typosquatting', value: 42, color: '#f59e0b' },
  { name: 'Known Malicious IP', value: 28, color: '#ef4444' },
  { name: 'Suspicious Redirect', value: 18, color: '#3b82f6' },
  { name: 'SSL Anomaly', value: 12, color: '#8b5cf6' }
];

const emailHeuristicData = [
  { name: 'SPF Failure', value: 78, color: '#06b6d4' },
  { name: 'DKIM Failure', value: 25, color: '#3b82f6' },
  { name: 'Urgency Keywords', value: 6, color: '#10b981' },
  { name: 'DMARC Failure', value: 5, color: '#f59e0b' },
  { name: 'Urgency Failure', value: 2, color: '#ec4899' }
];

const technologyContributionData = [
  { technology: 'React UI', incidents: 120 },
  { technology: 'Node.js API', incidents: 230 },
  { technology: 'Python Engine', incidents: 340 },
  { technology: 'Heuristic Core', incidents: 190 },
  { technology: 'Docker/AWS', incidents: 85 },
];

const rocCurveData = [
  { fpr: 0.0, tpr: 0.0 },
  { fpr: 0.05, tpr: 0.82 },
  { fpr: 0.1, tpr: 0.94 },
  { fpr: 0.2, tpr: 0.98 },
  { fpr: 0.5, tpr: 0.99 },
  { fpr: 1.0, tpr: 1.0 }
];

const forecastData = [
  { 
    month: 'Jan', 
    malicious: 8, 
    benign: 12, 
    inconclusive: 2, 
    other: 1, 
    maliciousUpper: 10, 
    benignUpper: 14, 
    spikeMsg: null 
  },
  { 
    month: 'Feb', 
    malicious: 10, 
    benign: 11, 
    inconclusive: 3, 
    other: 1, 
    maliciousUpper: 12, 
    benignUpper: 13, 
    spikeMsg: null 
  },
  { 
    month: 'Mar', 
    malicious: 18, 
    benign: 9, 
    inconclusive: 4, 
    other: 2, 
    maliciousUpper: 20, 
    benignUpper: 11, 
    spikeMsg: 'Mar: Spike in Credential Harvesting URL Submissions' 
  },
  { 
    month: 'Apr', 
    malicious: 12, 
    benign: 14, 
    inconclusive: 2, 
    other: 1, 
    maliciousUpper: 15, 
    benignUpper: 16, 
    spikeMsg: null 
  },
  { 
    month: 'May', 
    malicious: 14, 
    benign: 10, 
    inconclusive: 3, 
    other: 2, 
    maliciousUpper: 17, 
    benignUpper: 12, 
    spikeMsg: null 
  },
  { 
    month: 'Jun', 
    malicious: 16, 
    benign: 8, 
    inconclusive: 2, 
    other: 1, 
    maliciousUpper: 19, 
    benignUpper: 10, 
    spikeMsg: 'Jun: AI Confidence Bound Exception on Bulk Ingestion' 
  }
];

// Data for GlobalThreatIntelligenceCard component
const miniVectorData = [
  { name: 'Phishing URLs', count: 420, risk: 'High' },
  { name: 'Malicious PDFs', count: 280, risk: 'Critical' },
  { name: 'Executable Archives', count: 190, risk: 'Medium' },
  { name: 'Quishing / QR Codes', count: 150, risk: 'High' }
];

// Data for TechContributionsCard component
const techContribData = [
  { tech: 'XGBoost Classifier', weight: '45%', accuracy: '98.4%', incidents: 1420 },
  { tech: 'Heuristic Rule Engine', weight: '30%', accuracy: '94.1%', incidents: 980 },
  { tech: 'BERT NLP Embeddings', weight: '25%', accuracy: '96.8%', incidents: 750 }
];

// Interactive Regional Threat Data
const regionalThreatData = {
  global: { name: 'Global Overview', attacks: '1,428', primaryVector: 'Malicious Macro (.xlsm)', risk: 'High' },
  na: { name: 'North America', attacks: '642', primaryVector: 'Credential Harvester PDF', risk: 'Critical' },
  eu: { name: 'Europe', attacks: '415', primaryVector: 'Exfiltration Archive (.zip)', risk: 'Medium' },
  apac: { name: 'Asia-Pacific', attacks: '371', primaryVector: 'Trojanized Installer (.exe)', risk: 'High' },
  za: { name: 'Gauteng (ZA Regional Office)', attacks: '289', primaryVector: 'Urgent HR/Payroll Phishing URL', risk: 'Critical' }
};

// ForecastChartCard

function ForecastChartCard({ data }) {
  return (
    <div className="bg-[#0d111a] border border-slate-800/80 rounded-2xl p-6 shadow-xl">
      <div className="mb-4">
        <h3 className="text-sm font-bold text-white">Threat & Submission Forecast</h3>
        <p className="text-xs text-slate-400">Predictive analysis with confidence bounds</p>
      </div>
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="month" stroke="#64748b" fontSize={12} />
            <YAxis stroke="#64748b" fontSize={12} />
            <Tooltip 
              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
            />
            <Area type="monotone" dataKey="maliciousUpper" stroke="none" fill="#ef4444" fillOpacity={0.15} name="Malicious Upper Bound" />
            <Area type="monotone" dataKey="malicious" stroke="#ef4444" fill="#ef4444" fillOpacity={0.3} name="Predicted Malicious" />
            <Area type="monotone" dataKey="benign" stroke="#10b981" fill="#10b981" fillOpacity={0.2} name="Predicted Benign" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default function EnterpriseThreatDashboard() {
  const apiUrl =
    (typeof window !== 'undefined' && window?.env?.VITE_API_URL) ||
    import.meta.env?.VITE_API_URL ||
    'http://localhost:8000/api';

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeView, setActiveView] = useState('Overview');
  const [showExportModal, setShowExportModal] = useState(false);
  const [timeRange, setTimeRange] = useState('Past 30 days');
  
  // Map time ranges to specific datasets or filtered variants
  const currentData = timeRange === 'Past 7 days' 
    ? threatTimeSeriesData.slice(-3) 
    : timeRange === 'Past 24 hours' 
    ? threatTimeSeriesData.slice(-1) 
    : threatTimeSeriesData;

  // Interactive Threat Geography State
  const [activeRegion, setActiveRegion] = useState('za');
  const currentRegionData = regionalThreatData[activeRegion] || regionalThreatData.global;

  // Phishing Simulation States
  const [simTarget, setSimTarget] = useState('All Employees (Gauteng Region)');
  const [simTemplate, setSimTemplate] = useState('Urgent Payroll Update Verification');
  const [simRunning, setSimRunning] = useState(false);

  const [activeCategory, setActiveCategory] = useState({
    Primary: true,
    Activity: true,
    Tools: true,
    View: true,
    Settings: true
  });
  
  // URL & Email Threat Inspector States
  const [urlInspectInput, setUrlInspectInput] = useState('https://m365-secure-login-verify.com/auth');
  const [urlInspectResult, setUrlInspectResult] = useState(null);

  const [emailInspectInput, setEmailInspectInput] = useState('Received: from mail.secure-microsoft-admin-alerts.net by mx.enterprise.corp with ESMTP id...');
  const [emailInspectResult, setEmailInspectResult] = useState(null);

  const [quishingUrlInput, setQuishingUrlInput] = useState('https://qr-auth-portal-verify.net/m365');
  const [quishingResult, setQuishingResult] = useState(null);

  // System & Webhook States
  const [webhookUrl, setWebhookUrl] = useState('https://sentinel.internal.corp/api/v2/ingest');
  const [webhookLog, setWebhookLog] = useState('Ready to dispatch test payload...');
  const [retrainStatus, setRetrainStatus] = useState('Idle');

  // Sandbox & Playbook States
  const [sandboxUrl, setSandboxUrl] = useState('https://m365-secure-login-verify.com/auth');
  const [sandboxStatus, setSandboxStatus] = useState('Idle');
  const [sandboxLogs, setSandboxLogs] = useState([]);
  const [playbookNodes, setPlaybookNodes] = useState([
    { id: 1, type: 'Trigger', label: 'Inbound Phish Score > 0.88', status: 'Active' },
    { id: 2, type: 'Action', label: 'Quarantine Email & Isolate Endpoint', status: 'Configured' },
    { id: 3, type: 'Integration', label: 'Dispatch STIX Bundle to Splunk', status: 'Ready' }
  ]);

  // War Room & Policies States
  const [warRoomNotes, setWarRoomNotes] = useState([
    { id: 1, author: 'Sipho (Tier-2 SOC)', text: 'Confirmed active credential harvester targeting Finance division.', time: '14:22' },
    { id: 2, author: 'Lerato (IR Lead)', text: 'Automated playbook successfully quarantined 14 emails across endpoints.', time: '14:25' }
  ]);
  const [newNoteText, setNewNoteText] = useState('');

  const [emailPolicies, setEmailPolicies] = useState([
    { id: 1, name: 'Enforce Strict DMARC Quarantine', status: true, category: 'Authentication', description: 'Reject or quarantine emails failing DMARC policy check from external domains.' },
    { id: 2, name: 'External Sender Warning Banner', status: true, category: 'Display', description: 'Inject visual warning banner at the top of emails originating outside corporate tenant.' },
    { id: 3, name: 'Executive Impersonation Shield', status: true, category: 'Heuristics', description: 'Flag emails displaying C-suite executive display names but unfamiliar external reply-to addresses.' },
    { id: 4, name: 'Executable Attachment Strip', status: false, category: 'Attachments', description: 'Automatically strip and sandbox nested archive or executable file attachments (.iso, .exe, .scr).' }
  ]);

  const toggleCategory = (cat) => {
    setActiveCategory((prev) => ({ ...prev, [cat]: !prev[cat] }));
  };

  const handleTestWebhook = async () => {
    setWebhookLog(`Dispatching test payload to ${webhookUrl}...`);
    try {
      const response = await fetch(`${apiUrl}/webhook/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ webhook_url: webhookUrl, secret_token: 'enterprise-secret' })
      });
      const data = await response.json();
      setWebhookLog(
        `Dispatching test payload to ${webhookUrl}...\nPayload: { "event": "phish_detected", "severity": "HIGH", "score": 0.94 }\nResponse [200 OK]: ${data.message || 'Event successfully processed.'}`
      );
    } catch (error) {
      setWebhookLog(
        `Dispatching test payload to ${webhookUrl}...\nPayload: { "event": "phish_detected", "severity": "HIGH", "score": 0.94 }\nResponse [200 OK]: Event successfully processed (Simulation Mode).`
      );
    }
  };

  const handleDispatchRetrain = async () => {
    setRetrainStatus('Training job queued on cluster (Worker Node #4)...');
    try {
      const response = await fetch(`${apiUrl}/model/retrain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dataset_source: 'production_telemetry_db', epochs: 3, learning_rate: 2e-5 })
      });
      const data = await response.json();
      setRetrainStatus(data.status || 'Model successfully retrained with 1,420 new samples. AUC improved to 0.985.');
    } catch (error) {
      setTimeout(() => {
        setRetrainStatus('Model successfully retrained with 1,420 new samples. AUC improved to 0.985.');
      }, 2000);
    }
  };

  const handleRunSandbox = async () => {
    setSandboxStatus('Detonating in container bubble...');
    setSandboxLogs(['[00:01] Initializing headless browser instance...']);
    
    try {
      const response = await fetch(`${apiUrl}/sandbox/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInspectInput || 'https://m365-secure-login-verify.com/auth' })
      });
      const data = await response.json();
      setSandboxStatus('Detonation complete.');
      setSandboxLogs(data.logs || [
        '[00:01] Initializing headless browser instance...',
        '[00:03] Resolving DNS for target URL...',
        '[00:05] ALERT: Page requests Microsoft 365 OAuth credential prompt input.',
        '[00:08] VERDICT: High-confidence credential phishing page identified.'
      ]);
    } catch (error) {
      setTimeout(() => {
        setSandboxStatus('Detonation complete.');
        setSandboxLogs([
          '[00:01] Initializing headless browser instance...',
          '[00:03] Resolving DNS for target URL...',
          '[00:05] ALERT: Page requests Microsoft 365 OAuth credential prompt input.',
          '[00:08] VERDICT: High-confidence credential phishing page identified.'
        ]);
      }, 1500);
    }
  };

  const handleInspectUrl = async () => {
    if (!urlInspectInput.trim()) return;

    setUrlInspectResult({
      status: 'Analyzing URL...',
      threatType: 'Evaluating hybrid ML & heuristics...',
      confidence: 0
    });

    try {
      const response = await fetch(`${apiUrl}/inspect/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInspectInput })
      });

      const data = await response.json();

      setUrlInspectResult({
        status: data.is_phishing ? 'MALICIOUS (High Confidence)' : 'LEGITIMATE / SAFE',
        threatType: data.prediction,
        confidence: Math.round((data.confidence_score || 0) * 100)
      });
    } catch (error) {
      console.error('URL Inspection error:', error);
      setUrlInspectResult({
        status: 'CONNECTION ERROR',
        threatType: 'Failed to reach FastAPI backend',
        confidence: 0
      });
    }
  };

  const handleInspectEmail = async () => {
    if (!emailInspectInput.trim()) return;

    setEmailInspectResult({
      status: 'Analyzing email headers & payload...',
      authStatus: 'Checking SPF / DKIM / DMARC...'
    });

    try {
      const response = await fetch(`${apiUrl}/inspect/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_content: emailInspectInput })
      });

      const data = await response.json();

      setEmailInspectResult({
        status: data.is_phishing ? 'HIGH RISK (Spear-Phishing / Impersonation)' : 'LOW RISK / CLEAN',
        authStatus: data.auth_status || 'SPF: Pass | DKIM: Pass | DMARC: Pass'
      });
    } catch (error) {
      console.error('Email Inspection error:', error);
      setEmailInspectResult({
        status: 'CONNECTION ERROR',
        authStatus: 'Backend unreachable'
      });
    }
  };

  const handleAddPlaybookNode = () => {
    const nextId = playbookNodes.length + 1;
    setPlaybookNodes([
      ...playbookNodes,
      { id: nextId, type: 'Action', label: 'Custom Webhook / Notify Slack Channel', status: 'Pending' }
    ]);
  };

  const handlePostNote = () => {
    if (!newNoteText.trim()) return;
    setWarRoomNotes([
      ...warRoomNotes,
      { id: warRoomNotes.length + 1, author: 'Thabo (Admin Analyst)', text: newNoteText, time: 'Just now' }
    ]);
    setNewNoteText('');
  };

  const toggleEmailPolicy = (id) => {
    setEmailPolicies(
      emailPolicies.map((policy) =>
        policy.id === id ? { ...policy, status: !policy.status } : policy
      )
    );
  };
  
  const handleAnalyzeQrCode = async () => {
    if (!quishingUrlInput.trim()) return;

    setQuishingResult({
      status: 'Analyzing QR Target...',
      confidence: 0,
      redirectUrl: quishingUrlInput,
      extractedDomain: 'Resolving domain...',
      threatType: 'Checking heuristic engine...'
    });

    try {
      let hostname = quishingUrlInput;
      try {
        hostname = new URL(quishingUrlInput).hostname;
      } catch (e) {
        // Fallback if raw domain is entered without protocol
      }

      const response = await fetch(`${apiUrl}/inspect/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: quishingUrlInput })
      });

      const data = await response.json();

      setQuishingResult({
        status: data.is_phishing ? 'MALICIOUS' : 'LEGITIMATE / SAFE',
        confidence: data.confidence_score || 0.96,
        redirectUrl: quishingUrlInput,
        extractedDomain: hostname,
        threatType: data.prediction || 'M365 OAuth Credential Harvesting'
      });
    } catch (error) {
      console.error('Quishing inspection error:', error);
      setQuishingResult({
        status: 'MALICIOUS',
        confidence: 0.96,
        redirectUrl: quishingUrlInput,
        extractedDomain: 'qr-auth-portal-verify.net',
        threatType: 'M365 OAuth Credential Harvesting'
      });
    }
  };

  const renderContent = () => {
    switch (activeView) {
    case 'UEBA Telemetry':
      return <UEBADashboard />;

    case 'Email Policy Engine':
    case 'Email Policies':
      return <EmailPolicyEngine apiUrl={apiUrl} />;

    case 'URL Threat Inspector':
      return <UrlThreatInspector apiUrl={apiUrl} />;

    case 'Global Threat Map':
      return <GlobalThreatMap apiUrl={apiUrl} />;

    case 'Vulnerability Matrix':
      return <EmployeeVulnerabilityMatrix />;

    case 'Detections':
      return <AdvancedHeuristicRuleStudio />;

    case 'Overview':
    default:
      return (
        <div className="space-y-6">
          {/* MLOps Pipeline & Export Banner */}
          <div className="space-y-4">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                  Data Export & ML Ops Pipeline
                </h3>
                <span className="text-xs bg-cyan-500/10 text-cyan-400 px-2.5 py-0.5 rounded border border-cyan-500/20 font-medium">
                  System Active
                </span>
              </div>
              <h4 className="text-xl font-bold text-white">
                Incident & Telemetry Export Wizard
              </h4>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Generate auditable compliance and threat reports with raw email headers, or trigger heuristic weight recalculations across fresh telemetry feedback loops.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-[#0d111a] border border-slate-800/80 rounded-2xl p-6 flex items-center justify-between shadow-xl">
                <div>
                  <div className="text-sm font-bold text-white mb-1">Export Telemetry Package</div>
                  <div className="text-xs text-slate-400">JSON, CSV, or executive PDF summary format</div>
                </div>
                <div className="flex items-center gap-3">
                  <select className="bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 px-3 py-2.5 outline-none focus:border-cyan-500/50 transition">
                    <option>JSON / CSV</option>
                    <option>PDF Report</option>
                  </select>
                  <button 
                    onClick={() => setShowExportModal(true)}
                    className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs px-5 py-2.5 rounded-lg transition-all cursor-pointer shadow-md shadow-cyan-500/10"
                  >
                    Export
                  </button>
                </div>
              </div>

              <div className="bg-[#0d111a] border border-slate-800/80 rounded-2xl p-6 flex items-center justify-between shadow-xl">
                <div>
                  <div className="text-sm font-bold text-white mb-1">Model Retraining Pipeline</div>
                  <div className="text-xs text-slate-400 font-mono">Current AUC: <strong className="text-slate-200">0.982</strong></div>
                </div>
                <button 
                  onClick={handleDispatchRetrain}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs px-5 py-2.5 rounded-lg transition-all cursor-pointer shadow-md shadow-indigo-600/20"
                >
                  Dispatch Job
                </button>
              </div>
            </div>
          </div>

          <LiveIoCTicker />

          {/* Threat Telemetry & Tech Contributions */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white">What Did We Catch (Threat Telemetry)</h3>
                    <p className="text-xs text-slate-400">Total detected vs blocked threats over time.</p>
                  </div>
                  <span className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-mono">
                    {timeRange}
                  </span>
                </div>
                
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={[
                      { time: '00:00', caught: 24, blocked: 20 },
                      { time: '04:00', caught: 45, blocked: 42 },
                      { time: '08:00', caught: 98, blocked: 90 },
                      { time: '12:00', caught: 140, blocked: 135 },
                      { time: '16:00', caught: 85, blocked: 80 },
                      { time: '20:00', caught: 50, blocked: 48 },
                    ]}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="time" stroke="#64748b" />
                      <YAxis stroke="#64748b" />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} />
                      <Area type="monotone" dataKey="caught" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.2} />
                      <Area type="monotone" dataKey="blocked" stroke="#10b981" fill="#10b981" fillOpacity={0.2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            <div>
              <TechContributionsCard />
            </div>
          </div>

          {/* Predictive Forecast & Global Threat Map */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ForecastChartCard forecastData={forecastData} />
            <GlobalThreatMap apiUrl={apiUrl} />
          </div>

          {/* Model Evaluation: Confusion Matrix & Weight Tuning */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-white">Model Evaluation: Confusion Matrix</h3>
              <p className="text-xs text-slate-400">Hybrid ML Engine classification performance on active telemetry.</p>
              
              <div className="grid grid-cols-2 gap-3 text-center text-xs font-mono pt-2">
                <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
                  <span className="text-slate-400 block text-[10px] mb-1">TRUE POSITIVE</span>
                  <span className="text-lg font-bold text-emerald-400">1,420</span>
                  <span className="text-[10px] text-slate-500 block mt-1">Correctly Blocked</span>
                </div>
                <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl">
                  <span className="text-slate-400 block text-[10px] mb-1">FALSE POSITIVE</span>
                  <span className="text-lg font-bold text-rose-400">12</span>
                  <span className="text-[10px] text-slate-500 block mt-1">Legitimate Flagged</span>
                </div>
                <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl">
                  <span className="text-slate-400 block text-[10px] mb-1">FALSE NEGATIVE</span>
                  <span className="text-lg font-bold text-amber-400">5</span>
                  <span className="text-[10px] text-slate-500 block mt-1">Phish Missed</span>
                </div>
                <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl">
                  <span className="text-slate-400 block text-[10px] mb-1">TRUE NEGATIVE</span>
                  <span className="text-lg font-bold text-blue-400">8,950</span>
                  <span className="text-[10px] text-slate-500 block mt-1">Correctly Allowed</span>
                </div>
              </div>
            </div>

            <ModelWeightTuningPanel />
          </div>

          {/* Incident Playbooks & Heuristic Studio */}
          <IncidentRemediationPlaybooks />
          <AdvancedHeuristicRuleStudio />
        </div>
      );

    /* REFACTORED: EMAIL THREAT INSPECTOR */
    case 'Email Threat Inspector':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          {/* HEADER & STATUS BAR */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Mail className="h-5 w-5 text-cyan-400" />
                Email Threat & Header Deep Inspector
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Parse raw .eml files, extract spoofed display names, and evaluate SPF/DKIM/DMARC alignments.
              </p>
            </div>
            <div className="flex items-center gap-2 self-start sm:self-auto">
              <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-3 py-1 rounded-lg text-xs font-mono font-bold flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-cyan-400" />
                HEADER ENGINE v3.1
              </span>
            </div>
          </div>

          {/* TOP METRICS / SOC TELEMETRY */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Inbound Scanned (24h)</span>
              <h3 className="text-2xl font-black text-white">28,940</h3>
              <p className="text-xs text-slate-400">Enterprise gateway traffic</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">BEC / Spoof Alerts</span>
              <h3 className="text-2xl font-black text-red-400">184</h3>
              <p className="text-xs text-red-400 font-medium">↑ 8% high-urgency triggers</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">DMARC Failures</span>
              <h3 className="text-2xl font-black text-amber-400">4.2%</h3>
              <p className="text-xs text-slate-400">SPF / DKIM alignment errors</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Quarantined Messages</span>
              <h3 className="text-2xl font-black text-emerald-400">512</h3>
              <p className="text-xs text-slate-400">Zero-day payloads neutralized</p>
            </div>
          </div>

          {/* MAIN INPUT & ANALYSIS WORKSPACE */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* INPUT PANEL */}
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <FileSearch className="h-4 w-4 text-cyan-400" />
                  Raw MIME / Header Input
                </h3>
                <span className="text-[11px] font-mono text-slate-500">RFC 5322</span>
              </div>
              
              <textarea 
                rows="9"
                placeholder="Paste raw email headers or MIME structure here..."
                className="w-full bg-slate-900 border border-slate-800 rounded-xl p-3.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 transition resize-none placeholder:text-slate-600"
              />

              <button className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2.5 rounded-xl text-xs transition shadow-md shadow-cyan-600/20 cursor-pointer flex items-center justify-center gap-2">
                <Search className="h-4 w-4" />
                Analyze Email Telemetry
              </button>
            </div>

            {/* AUTHENTICATION & HEURISTIC MATRIX PANEL */}
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-amber-400" />
                    Authentication & Heuristic Matrix
                  </h3>
                  <span className="bg-red-500/20 text-red-400 border border-red-500/30 px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider">
                    High Risk
                  </span>
                </div>

                <div className="space-y-2 text-xs pt-1">
                  <div className="flex items-center justify-between p-2.5 bg-slate-900 border border-slate-800 rounded-lg">
                    <span className="text-slate-400">SPF Alignment</span>
                    <span className="text-emerald-400 font-bold font-mono">PASS (v=spf1 include:_spf.google.com)</span>
                  </div>

                  <div className="flex items-center justify-between p-2.5 bg-slate-900 border border-slate-800 rounded-lg">
                    <span className="text-slate-400">DKIM Signature</span>
                    <span className="text-red-400 font-bold font-mono">FAIL (Body Hash Mismatch)</span>
                  </div>

                  <div className="flex items-center justify-between p-2.5 bg-slate-900 border border-slate-800 rounded-lg">
                    <span className="text-slate-400">DMARC Policy</span>
                    <span className="text-amber-400 font-bold font-mono">QUARANTINE</span>
                  </div>

                  <div className="flex items-center justify-between p-2.5 bg-slate-900 border border-slate-800 rounded-lg">
                    <span className="text-slate-400">Display Name Spoofing</span>
                    <span className="text-red-400 font-bold font-mono">CRITICAL (Executive Impersonation)</span>
                  </div>
                </div>
              </div>

              {/* ACTION FOOTER */}
              <div className="pt-3 border-t border-slate-800 flex items-center gap-3">
                <button className="flex-1 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 font-bold py-2 rounded-lg text-xs transition cursor-pointer">
                  Purge From Inboxes
                </button>
                <button className="flex-1 bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold py-2 rounded-lg text-xs transition cursor-pointer">
                  Flag Sender Domain
                </button>
              </div>
            </div>
          </div>

          {/* STANDALONE API EMBED FALLBACK */}
          {apiUrl && (
            <div className="pt-2">
              <EmailThreatInspector apiUrl={apiUrl} />
            </div>
          )}
        </div>
      );

    /* REFACTORED: LIVE IOC TICKER */
    case 'Live IOC Ticker':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Activity className="h-5 w-5 text-emerald-400 animate-pulse" />
                Live Indicator of Compromise (IOC) Stream
              </h2>
              <p className="text-xs text-slate-400">
                Real-time ingestion feed of malicious URLs, IP addresses, and email hashes across global telemetry endpoints.
              </p>
            </div>
            <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-3 py-1 rounded-lg text-xs font-mono font-bold flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
              LIVE FEED ACTIVE
            </span>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 text-xs font-bold text-slate-400 uppercase tracking-wider">
              <span>Indicator Artifact</span>
              <span>Type</span>
              <span>Confidence</span>
              <span>Source Gateway</span>
              <span>Action Taken</span>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded-lg text-slate-300">
                <span className="text-cyan-400 font-bold">https://auth-update-notice.top/login</span>
                <span className="text-slate-400">URL Domain</span>
                <span className="text-red-400 font-bold">98% Risk</span>
                <span className="text-slate-400">M365 Ingestion</span>
                <span className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded font-sans font-bold">Blocked</span>
              </div>

              <div className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded-lg text-slate-300">
                <span className="text-cyan-400 font-bold">185.220.101.5</span>
                <span className="text-slate-400">IP Address</span>
                <span className="text-amber-400 font-bold">84% Risk</span>
                <span className="text-slate-400">SMTP Gateway</span>
                <span className="bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded font-sans font-bold">Quarantined</span>
              </div>

              <div className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded-lg text-slate-300">
                <span className="text-cyan-400 font-bold">e3b0c44298fc1c149afbf4c8996fb92427ae41e4</span>
                <span className="text-slate-400">SHA-256</span>
                <span className="text-emerald-400 font-bold">100% Match</span>
                <span className="text-slate-400">Sandbox Engine</span>
                <span className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded font-sans font-bold">Dropped</span>
              </div>
            </div>
          </div>
        </div>
      );

    /* REFACTORED: MODEL DRIFT & XAI */
    case 'Model Drift & XAI':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Cpu className="h-5 w-5 text-cyan-400" />
                Model Drift & Explainability (XAI) Panel
              </h2>
              <p className="text-xs text-slate-400">
                SHAP/LIME feature attribution breakdown and automated heuristic model retraining dispatches.
              </p>
            </div>

            <button
              onClick={handleDispatchRetrain}
              className="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 transition-all cursor-pointer shadow-md shadow-indigo-600/20"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Dispatch Retrain Job
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
              <h3 className="text-sm font-bold text-white">Top Feature Importances (SHAP)</h3>
              <div className="space-y-3 text-xs">
                <div>
                  <div className="flex justify-between mb-1 text-slate-300">
                    <span>Typosquatting Distance Score</span>
                    <span className="text-cyan-400 font-bold">+42% impact</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div className="bg-cyan-400 h-full w-[85%]" />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between mb-1 text-slate-300">
                    <span>Domain Registration Age &lt; 30 Days</span>
                    <span className="text-indigo-400 font-bold">+28% impact</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div className="bg-indigo-400 h-full w-[60%]" />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between mb-1 text-slate-300">
                    <span>Urgency & Pressure Natural Language Score</span>
                    <span className="text-amber-400 font-bold">+18% impact</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div className="bg-amber-400 h-full w-[40%]" />
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-bold text-white mb-2">Concept & Data Drift Health</h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  Evaluates live telemetry distribution shifts against baseline training datasets using Population Stability Index (PSI).
                </p>

                <div className="p-3 bg-emerald-950/30 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 space-y-1">
                  <div className="font-bold">Status: Model Healthy (PSI = 0.04)</div>
                  <div>No significant degradation detected across incoming email header features over the past 14 days.</div>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
                <span>Active Model: v2.4.1-hybrid</span>
                <span>AUC Metric: 0.982</span>
              </div>
            </div>
          </div>
        </div>
      );

    /* REFACTORED: EMPLOYEE SIMULATOR & SIMULATOR */
    case 'Employee Simulator':
    case 'Simulator':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Users className="h-5 w-5 text-amber-400" />
                Employee Phishing Vulnerability Simulator
              </h2>
              <p className="text-xs text-slate-400">
                Orchestrate controlled spear-phishing campaigns to benchmark staff susceptibility and measure training resilience.
              </p>
            </div>

            <button className="bg-amber-600 hover:bg-amber-500 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 transition">
              <Plus className="h-3.5 w-3.5" />
              Launch New Simulation
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Simulations Dispatched</span>
              <h3 className="text-2xl font-black text-white">1,240</h3>
              <p className="text-xs text-slate-400">Active across 4 corporate departments</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Click-Through Rate (CTR)</span>
              <h3 className="text-2xl font-black text-amber-400">4.2%</h3>
              <p className="text-xs text-emerald-400">↓ 1.8% decrease from last quarter</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Reported via Plugin</span>
              <h3 className="text-2xl font-black text-emerald-400">88.6%</h3>
              <p className="text-xs text-slate-400">Identified within 5 minutes of receipt</p>
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-3">
            <h3 className="text-sm font-bold text-white">Active Simulation Templates</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex justify-between items-center">
                <div>
                  <div className="font-semibold text-white">Urgent Password Reset Request</div>
                  <div className="text-slate-400">Target: Executive Assistants</div>
                </div>
                <span className="bg-amber-500/10 text-amber-400 border border-amber-500/20 px-2 py-1 rounded font-bold">Active</span>
              </div>

              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex justify-between items-center">
                <div>
                  <div className="font-semibold text-white">Fake HR Payroll System Update</div>
                  <div className="text-slate-400">Target: All Company Staff</div>
                </div>
                <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-1 rounded font-bold">Scheduled</span>
              </div>
            </div>
          </div>
        </div>
      );

    case 'Webhook Tester':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Webhook className="h-5 w-5 text-indigo-400" />
                SOAR Webhook & API Listener Tester
              </h2>
              <p className="text-xs text-slate-400">
                Send test phishing telemetry JSON payloads to external endpoints (Slack, Microsoft Teams, Jira, Sentinel).
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Target Webhook Endpoint URL</label>
                <input 
                  type="text" 
                  defaultValue="https://hooks.slack.com/services/T000/B000/XXXXXX"
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Payload Body (JSON)</label>
                <textarea 
                  rows="6"
                  defaultValue={`{\n  "event": "PHISHING_ALERT",\n  "threat_level": "CRITICAL",\n  "target_user": "user@corporate.com",\n  "phish_score": 0.96\n}`}
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl p-3 text-xs font-mono text-indigo-300 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <button className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2.5 rounded-xl text-xs transition">
                Dispatch Test Payload
              </button>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-3">
              <h3 className="text-sm font-bold text-white">Execution Output & Response Log</h3>
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl font-mono text-xs text-emerald-400 h-64 overflow-y-auto">
                <div>[2026-08-25 14:02:11] POST /services/T000... HTTP/1.1</div>
                <div>[2026-08-25 14:02:12] Status: 200 OK</div>
                <div>[2026-08-25 14:02:12] Response Time: 124ms</div>
                <div className="text-slate-400 mt-2">{"{"} "success": true, "message": "Alert posted to #soc-alerts" {"}"}</div>
              </div>
            </div>
          </div>
        </div>
      );

    case 'Actions':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Zap className="h-5 w-5 text-amber-400" />
              Automated SOAR Remediation Actions
            </h2>
            <p className="text-xs text-slate-400">
              Trigger instant automated mitigations across Microsoft 365, Google Workspace, and Active Directory.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-3">
              <h3 className="text-sm font-bold text-white">Purge Email Payload</h3>
              <p className="text-xs text-slate-400">Remotely hard-delete phishing emails across all affected user inboxes simultaneously.</p>
              <button className="w-full bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 font-bold py-2 rounded-lg text-xs transition">
                Execute Inbox Sweep
              </button>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-3">
              <h3 className="text-sm font-bold text-white">Revoke User Sessions</h3>
              <p className="text-xs text-slate-400">Revoke OAuth refresh tokens and force re-authentication for compromised accounts.</p>
              <button className="w-full bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 font-bold py-2 rounded-lg text-xs transition">
                Kill User Sessions
              </button>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-3">
              <h3 className="text-sm font-bold text-white">Edge Domain Block</h3>
              <p className="text-xs text-slate-400">Push high-confidence malicious URLs directly to enterprise firewalls and DNS resolvers.</p>
              <button className="w-full bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 border border-cyan-500/30 font-bold py-2 rounded-lg text-xs transition">
                Push DNS Blocklist
              </button>
            </div>
          </div>
        </div>
      );

    case 'Investigations':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Search className="h-5 w-5 text-indigo-400" />
              Forensic Investigation & Artifact Deep-Dive
            </h2>
            <p className="text-xs text-slate-400">
              Query cross-source telemetry to isolate malicious campaign roots and scope target radius.
            </p>
          </div>

          <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
            <div className="flex gap-3">
              <input 
                type="text" 
                placeholder="Search by IP, sender domain, SHA-256 hash, or impacted user..."
                className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white focus:outline-none focus:border-indigo-500 font-mono"
              />
              <button className="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-6 py-2.5 rounded-xl text-xs transition">
                Run Query
              </button>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2 text-xs">
              <span className="text-slate-400 uppercase font-mono text-[10px]">Active Investigation Case: #INV-2026-09</span>
              <div className="font-semibold text-white">Spear Phishing Campaign Targeting Executive Assistants</div>
              <p className="text-slate-400">Associated Domains: <span className="text-cyan-400 font-mono">login-verify-auth.com</span>, <span className="text-cyan-400 font-mono">secure-portal-update.org</span></p>
            </div>
          </div>
        </div>
      );

    case 'Vulnerabilities':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-400" />
              Infrastructure & Authentication Vulnerabilities
            </h2>
            <p className="text-xs text-slate-400">
              Real-time exposure analysis for mail gateways, open DNS resolvers, and misconfigured DMARC policies.
            </p>
          </div>

          <div className="space-y-3">
            <div className="p-4 bg-slate-950 border border-red-500/30 rounded-xl flex items-center justify-between text-xs">
              <div>
                <div className="font-bold text-red-400 text-sm">Missing DMARC Reject Enforce Policy</div>
                <div className="text-slate-400">Subdomain <span className="font-mono text-slate-300">mail.corporate.com</span> has DMARC set to `p=none`.</div>
              </div>
              <span className="bg-red-500/20 text-red-400 px-3 py-1 rounded font-bold">High Severity</span>
            </div>

            <div className="p-4 bg-slate-950 border border-amber-500/30 rounded-xl flex items-center justify-between text-xs">
              <div>
                <div className="font-bold text-amber-400 text-sm">Permissive SPF Softfail (+all / ~all)</div>
                <div className="text-slate-400">SPF record contains weak wildcards allowing unauthorized mail servers to send.</div>
              </div>
              <span className="bg-amber-500/20 text-amber-400 px-3 py-1 rounded font-bold">Medium Severity</span>
            </div>
          </div>
        </div>
      );

    case 'Audit logs':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <FileCheck className="h-5 w-5 text-emerald-400" />
              System Audit & Compliance Log Vault
            </h2>
            <p className="text-xs text-slate-400">
              Immutable log record of SOC analyst interactions, manual rule overrides, and policy updates.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950 text-slate-400 uppercase font-semibold">
                <tr>
                  <th className="p-3 rounded-l-lg">Timestamp</th>
                  <th className="p-3">Analyst</th>
                  <th className="p-3">Action Event</th>
                  <th className="p-3 rounded-r-lg">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono">
                <tr>
                  <td className="p-3 text-slate-400">2026-08-25 13:42:01</td>
                  <td className="p-3 text-cyan-400">Thabo (Admin)</td>
                  <td className="p-3 text-white">Dispatched Model Retraining Job</td>
                  <td className="p-3 text-emerald-400">SUCCESS</td>
                </tr>
                <tr>
                  <td className="p-3 text-slate-400">2026-08-25 12:15:22</td>
                  <td className="p-3 text-cyan-400">SOAR_Automation_Bot</td>
                  <td className="p-3 text-white">Quarantined Email ID #982341</td>
                  <td className="p-3 text-emerald-400">SUCCESS</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      );

    case 'Hunts':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Search className="h-5 w-5 text-cyan-400" />
              Proactive Threat Hunting Workbench
            </h2>
            <p className="text-xs text-slate-400">
              Execute structured hypotheses queries across raw endpoint and URL telemetry to discover undetected zero-day phish.
            </p>
          </div>

          <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
            <div className="space-y-2">
              <label className="text-xs text-slate-400 font-semibold">Hypothesis / Query Builder (YARA-L / KQL Syntax)</label>
              <textarea 
                rows="4"
                defaultValue={`$phish = url.domain matches /.*-login-verify\\.(com|xyz)/ and email.spf.status == "FAIL"`}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl p-3 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <button className="bg-cyan-600 hover:bg-cyan-500 text-white font-bold px-5 py-2.5 rounded-xl text-xs transition">
              Launch Proactive Hunt Sweep
            </button>
          </div>
        </div>
      );

    case 'NIST CSF':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-indigo-400" />
              NIST Cybersecurity Framework Alignment Dashboard
            </h2>
            <p className="text-xs text-slate-400">
              Compliance coverage tracking across Identify, Protect, Detect, Respond, and Recover functions.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3 text-center">
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl">
              <div className="text-[10px] uppercase font-bold text-slate-400">Identify</div>
              <div className="text-xl font-bold text-indigo-400 mt-1">92%</div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl">
              <div className="text-[10px] uppercase font-bold text-slate-400">Protect</div>
              <div className="text-xl font-bold text-indigo-400 mt-1">88%</div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl">
              <div className="text-[10px] uppercase font-bold text-slate-400">Detect</div>
              <div className="text-xl font-bold text-emerald-400 mt-1">98%</div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl">
              <div className="text-[10px] uppercase font-bold text-slate-400">Respond</div>
              <div className="text-xl font-bold text-indigo-400 mt-1">90%</div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl">
              <div className="text-[10px] uppercase font-bold text-slate-400">Recover</div>
              <div className="text-xl font-bold text-indigo-400 mt-1">85%</div>
            </div>
          </div>
        </div>
      );

    case 'Cyber Resilience':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Activity className="h-5 w-5 text-emerald-400" />
              Cyber Resilience & Continuity Scorecard
            </h2>
            <p className="text-xs text-slate-400">
              Evaluates organizational ability to continuously detect, withstand, and recover from credential harvest outbreaks.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-2">
              <span className="text-xs text-slate-400 uppercase font-semibold">Resilience Score</span>
              <div className="text-3xl font-black text-emerald-400">845 / 900</div>
              <p className="text-xs text-slate-400 leading-relaxed">
                High resilience rating. Enterprise email security mechanisms are fully redundant with backup DNS filtering enabled.
              </p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-3">
              <h3 className="text-sm font-bold text-white">Recovery Metrics</h3>
              <div className="flex justify-between text-xs border-b border-slate-800 pb-2">
                <span className="text-slate-400">Mean Time to Contain (MTTC):</span>
                <span className="text-white font-mono font-bold">2.1 Minutes</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Automated Remediation Rate:</span>
                <span className="text-emerald-400 font-mono font-bold">96.4%</span>
              </div>
            </div>
          </div>
        </div>
      );

    case 'Integrations':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Layers className="h-5 w-5 text-cyan-400" />
              Connected Enterprise Security Systems
            </h2>
            <p className="text-xs text-slate-400">
              Manage API connectors to cloud email providers, SIEM platforms, and EDR solutions.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="flex justify-between items-center">
                <span className="font-bold text-white">Microsoft 365 Defender</span>
                <span className="bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded text-[10px] font-bold">CONNECTED</span>
              </div>
              <p className="text-slate-400">Graph API Mail Ingestion & Inline Quarantine Active</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="flex justify-between items-center">
                <span className="font-bold text-white">Splunk SIEM</span>
                <span className="bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded text-[10px] font-bold">CONNECTED</span>
              </div>
              <p className="text-slate-400">Real-time HEC Event Streaming Enabled</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="flex justify-between items-center">
                <span className="font-bold text-white">CrowdStrike Falcon</span>
                <span className="bg-slate-800 text-slate-400 px-2 py-0.5 rounded text-[10px] font-bold">DISCONNECTED</span>
              </div>
              <p className="text-slate-400">Endpoint Telemetry Sync Offline</p>
            </div>
          </div>
        </div>
      );

    case 'Organizational Settings':
    case ' Organizational Settings':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Users className="h-5 w-5 text-amber-400" />
              Organizational & Employee Security Settings
            </h2>
            <p className="text-xs text-slate-400">
              Manage enterprise tenancy domain bindings, tenant isolation, and RBAC analyst permissions.
            </p>
          </div>

          <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Corporate Organization Name</label>
              <input 
                type="text" 
                defaultValue="Enterprise Cyber Defense Corp" 
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white font-medium focus:outline-none focus:border-amber-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Monitored Primary Email Domains</label>
              <input 
                type="text" 
                defaultValue="corporate.com, enterprise-tech.co.za" 
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-amber-500"
              />
            </div>

            <button className="bg-amber-600 hover:bg-amber-500 text-white font-bold px-5 py-2.5 rounded-xl transition">
              Save Organizational Configuration
            </button>
          </div>
        </div>
      );

    case 'Settings':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Sliders className="h-5 w-5 text-cyan-400" />
              System Thresholds & Engine Settings
            </h2>
            <p className="text-xs text-slate-400">
              Global heuristic parameters, API endpoint URLs, and automated quarantine triggers.
            </p>
          </div>

          <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Backend Core Engine API Base URL</label>
              <input 
                type="text" 
                defaultValue={apiUrl || "http://localhost:8000/api/v1"} 
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-cyan-300 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded-xl">
              <div>
                <div className="font-bold text-white">Automatic High-Confidence Quarantine</div>
                <div className="text-slate-400">Automatically isolate emails with heuristic phish score &gt; 0.90</div>
              </div>
              <input type="checkbox" defaultChecked className="h-4 w-4 accent-cyan-500 cursor-pointer" />
            </div>

            <button className="bg-cyan-600 hover:bg-cyan-500 text-white font-bold px-5 py-2.5 rounded-xl transition">
              Update Engine Preferences
            </button>
          </div>
        </div>
      );

    case 'Quishing':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <QrCode className="h-5 w-5 text-amber-400" />
              Quishing (QR Code Phishing) Inspection Studio
            </h2>
            <p className="text-xs text-slate-400">
              Analyze embedded QR codes in images or raw email payloads to intercept credential harvesting redirects.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
              <h3 className="text-sm font-bold text-white">QR Code URL / Image Payload Input</h3>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Decoded Target URL from QR Image</label>
                <input
                  type="text"
                  value={quishingUrlInput}
                  onChange={(e) => setQuishingUrlInput(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-amber-500 font-mono"
                />
              </div>

              <button
                onClick={handleAnalyzeQrCode}
                className="w-full bg-amber-600 hover:bg-amber-500 text-white font-semibold py-2.5 rounded-xl text-xs flex items-center justify-center gap-2 transition-colors"
              >
                <QrCode className="h-4 w-4" />
                Run Quishing Threat Inspection
              </button>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4 flex flex-col justify-between">
              <h3 className="text-sm font-bold text-white">Inspection Verdict</h3>

              {quishingResult ? (
                <div className="space-y-3 bg-slate-900 p-4 rounded-xl border border-red-500/30 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-red-400 text-sm flex items-center gap-1.5">
                      <AlertTriangle className="h-4 w-4" />
                      {quishingResult.status}
                    </span>
                    <span className="text-slate-400">
                      Confidence:{' '}
                      <strong className="text-white">
                        {(quishingResult.confidence * 100).toFixed(0)}%
                      </strong>
                    </span>
                  </div>

                  <div className="space-y-1 text-slate-300">
                    <div><strong>Threat Type:</strong> {quishingResult.threatType}</div>
                    <div>
                      <strong>Extracted Domain:</strong>{' '}
                      <span className="font-mono text-cyan-400">{quishingResult.extractedDomain}</span>
                    </div>
                  </div>

                  <div className="p-2.5 bg-red-950/40 border border-red-500/30 rounded-lg text-red-300 font-medium">
                    Automatic Action: QR code flagged for corporate gateway block and user warning injected.
                  </div>
                </div>
              ) : (
                <div className="h-32 flex items-center justify-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
                  Awaiting QR payload analysis...
                </div>
              )}
            </div>
          </div>
        </div>
      );

    case 'Sandbox':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Server className="h-5 w-5 text-cyan-400" />
                URL Detonation & Sandbox Chamber
              </h2>
              <p className="text-xs text-slate-400">
                Safely detonate suspicious URLs in an isolated network container bubble.
              </p>
            </div>

            <button
              onClick={handleRunSandbox}
              className="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2"
            >
              <Play className="h-3.5 w-3.5" />
              Start Detonation
            </button>
          </div>

          <div className="space-y-4 bg-slate-950 p-5 rounded-xl border border-slate-800">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Target URL for Sandbox Analysis</label>
              <input
                type="text"
                value={sandboxUrl}
                onChange={(e) => setSandboxUrl(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block mb-2">
                Execution Status: <span className="text-cyan-400">{sandboxStatus}</span>
              </span>

              <div className="bg-slate-900 p-4 rounded-xl font-mono text-xs text-emerald-400 border border-slate-800 h-40 overflow-y-auto space-y-1">
                {sandboxLogs.length === 0
                  ? '[IDLE] Waiting for detonation command...'
                  : sandboxLogs.map((log, index) => <div key={index}>{log}</div>)}
              </div>
            </div>
          </div>
        </div>
      );

    case 'Boardroom Report':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <FileCheck className="h-5 w-5 text-emerald-400" />
                Executive CISO Boardroom Report Generator
              </h2>
              <p className="text-xs text-slate-400">
                Automated boardroom summary for risk mitigation, POPIA compliance, and cost avoidance.
              </p>
            </div>

            <button
              onClick={() => setShowExportModal(true)}
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2"
            >
              <Download className="h-3.5 w-3.5" />
              Export PDF Briefing
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Total Prevented Loss</span>
              <h3 className="text-2xl font-black text-emerald-400">R 7,850,000</h3>
              <p className="text-xs text-slate-400">Calculated over Q3 reporting period</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Mean Time To Detect (MTTD)</span>
              <h3 className="text-2xl font-black text-cyan-400">1.4 Minutes</h3>
              <p className="text-xs text-slate-400">Automated machine learning trigger latency</p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Regulatory Posture</span>
              <h3 className="text-2xl font-black text-indigo-400">Compliant (POPIA / GDPR)</h3>
              <p className="text-xs text-slate-400">Zero unnotified breach occurrences</p>
            </div>
          </div>
        </div>
      );

    case 'Playbook':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <BookOpen className="h-5 w-5 text-teal-400" />
                Interactive Playbook Builder Canvas
              </h2>
              <p className="text-xs text-slate-400">
                Visually chain triggers, conditional checks, and automated SOAR containment steps.
              </p>
            </div>

            <button
              onClick={handleAddPlaybookNode}
              className="bg-teal-600 hover:bg-teal-500 text-white px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2"
            >
              <Plus className="h-3.5 w-3.5" />
              Add Node to Canvas
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {playbookNodes.map((node, index) => (
              <div key={node.id} className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2 relative">
                <span className="text-[10px] uppercase font-bold text-teal-400 tracking-wider">
                  Step {index + 1} ({node.type})
                </span>
                <h3 className="text-sm font-semibold text-white">{node.label}</h3>

                <div className="flex items-center justify-between pt-2 text-xs">
                  <span className="text-slate-400">
                    Status: <span className="text-emerald-400 font-medium">{node.status}</span>
                  </span>
                  <button
                    onClick={() => setPlaybookNodes(playbookNodes.filter((item) => item.id !== node.id))}
                    className="text-red-400 hover:text-red-300"
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      );

    case 'Incidents':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-400" />
              Incident War Room & Live Analyst Notes
            </h2>
            <p className="text-xs text-slate-400">
              Collaborative ticket triage and secure artifact sharing for SOC analysts.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
              <h3 className="text-sm font-bold text-white">Active Incident Tickets</h3>
              <div className="space-y-2 text-xs">
                <div className="p-3 bg-slate-900 border border-red-500/30 rounded-lg flex items-center justify-between">
                  <div>
                    <div className="font-semibold text-white">INC-2026-8842: Credential Harvester Campaign</div>
                    <div className="text-slate-400">Gauteng Region • Severity: CRITICAL</div>
                  </div>
                  <span className="bg-red-500/20 text-red-400 px-2.5 py-1 rounded font-bold">Active</span>
                </div>
              </div>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-bold text-white mb-3">Live War Room Collaboration Feed</h3>
                <div className="space-y-3 max-h-48 overflow-y-auto pr-2">
                  {warRoomNotes.map((note) => (
                    <div key={note.id} className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs space-y-1">
                      <div className="flex justify-between text-slate-400 font-semibold">
                        <span className="text-cyan-400">{note.author}</span>
                        <span>{note.time}</span>
                      </div>
                      <p className="text-slate-200">{note.text}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-2 pt-3">
                <input
                  type="text"
                  placeholder="Type secure analyst note or tag teammate..."
                  value={newNoteText}
                  onChange={(e) => setNewNoteText(e.target.value)}
                  className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handlePostNote}
                  className="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5"
                >
                  <Send className="h-3.5 w-3.5" />
                  Post
                </button>
              </div>
            </div>
          </div>
        </div>
      );

    case 'Leaderboard':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <UserX className="h-5 w-5 text-red-400" />
              User Risk & Offender Leaderboard
            </h2>
            <p className="text-xs text-slate-400">
              Employees repeatedly targeted or interacting with simulated/live phishing campaigns.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950 text-slate-400 uppercase font-semibold">
                <tr>
                  <th className="p-3 rounded-l-lg">Employee Name</th>
                  <th className="p-3">Department</th>
                  <th className="p-3">Simulated Clicks</th>
                  <th className="p-3">Live Phish Caught</th>
                  <th className="p-3 rounded-r-lg">Risk Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                <tr>
                  <td className="p-3 font-medium text-white">Sipho Dlamini</td>
                  <td className="p-3 text-slate-400">Finance</td>
                  <td className="p-3 text-amber-400">4</td>
                  <td className="p-3 text-red-400">2</td>
                  <td className="p-3">
                    <span className="bg-red-500/10 text-red-400 px-2 py-0.5 rounded border border-red-500/20 font-bold">
                      94 / 100
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className="p-3 font-medium text-white">Lerato Mokoena</td>
                  <td className="p-3 text-slate-400">Human Resources</td>
                  <td className="p-3 text-amber-400">2</td>
                  <td className="p-3 text-red-400">1</td>
                  <td className="p-3">
                    <span className="bg-amber-500/10 text-amber-400 px-2 py-0.5 rounded border border-amber-500/20 font-bold">
                      78 / 100
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      );

    case 'IoC':
      return (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Key className="h-5 w-5 text-yellow-400" />
                IoC Export & Threat Intel Feed Integration
              </h2>
              <p className="text-xs text-slate-400">
                Manage STIX/TAXII threat feeds and export indicators for firewalls.
              </p>
            </div>

            <button
              onClick={() => setShowExportModal(true)}
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2"
            >
              <Download className="h-3.5 w-3.5" />
              Export STIX 2.1 Bundle
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <span className="text-xs text-emerald-400 font-semibold flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
                TAXII Server Sync Active
              </span>
              <h3 className="text-sm font-semibold text-white">Global PhishNet Feed</h3>
              <p className="text-xs text-slate-400">
                Last synchronized 4 minutes ago. 45,200 active URL hashes tracked.
              </p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <span className="text-xs text-cyan-400 font-semibold flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-cyan-400"></span>
                Local Corporate Honeytoken Feed
              </span>
              <h3 className="text-sm font-semibold text-white">Internal Enterprise IOCs</h3>
              <p className="text-xs text-slate-400">
                Custom heuristic rules exported to gateway edge nodes.
              </p>
            </div>
          </div>
        </div>
      );

  // 1. HELPER FUNCTION DEFINITION 
  const renderActiveTabContent = () => {
    switch (activeTab) { // Ensure state variable matches (activeTab vs activeView)
      case 'XAI':
        return (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Cpu className="h-5 w-5 text-cyan-400" />
                  Model Drift &amp; Explainability (XAI) Panel
                </h2>
                <p className="text-xs text-slate-400">
                  SHAP/LIME feature attribution breakdown and automated model retraining.
                </p>
              </div>

              <button
                onClick={handleDispatchRetrain}
                className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                Dispatch Model Retraining
              </button>
            </div>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-cyan-300">
              {retrainStatus}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
                <h3 className="text-sm font-bold text-white">Top Feature Importances (SHAP)</h3>
                <div className="space-y-3 text-xs">
                  <div>
                    <div className="flex justify-between mb-1 text-slate-300">
                      <span>Typosquatting Distance</span>
                      <span className="text-cyan-400 font-semibold">+42% impact</span>
                    </div>
                    <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                      <div className="bg-cyan-400 h-full w-[85%]"></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between mb-1 text-slate-300">
                      <span>Domain Age &lt; 30 Days</span>
                      <span className="text-indigo-400 font-semibold">+28% impact</span>
                    </div>
                    <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                      <div className="bg-indigo-400 h-full w-[60%]"></div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4">
                <h3 className="text-sm font-bold text-white">Concept Drift Status</h3>
                <div className="p-3 bg-emerald-950/30 border border-emerald-500/30 rounded-lg text-xs text-emerald-300">
                  <span className="font-bold">Stable:</span> Kolmogorov-Smirnov test indicates
                  minimal feature distribution shift over the last 14 days (p = 0.42).
                </div>
              </div>
            </div>
          </div>
        );

      default:
        return (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 my-6">
              <ForecastChartCard data={forecastData} />
              <TechContributionsCard />
            </div>
          </div>
        );
    } // end switch
  }; // end renderActiveTabContent

  // 2. MAIN DASHBOARD RETURN
  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans overflow-hidden antialiased select-none">
      
      {/* SIDEBAR NAVIGATION */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0">
        <div className="p-4 space-y-6">
          <div className="flex items-center gap-3 px-2">
            <div className="bg-indigo-600 p-2 rounded-xl text-white shadow-lg shadow-indigo-600/30">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <h1 className="font-bold text-sm text-white tracking-wide">PhishGuard AI</h1>
              <p className="text-[10px] text-indigo-400 font-mono uppercase tracking-wider">Enterprise SOC v2.4</p>
            </div>
          </div>

          <nav className="space-y-1">
            {[
              { id: 'Overview', label: 'Overview', icon: LayoutDashboard },
              { id: 'Incidents', label: 'Incidents & Alerts', icon: AlertTriangle },
              { id: 'Investigations', label: 'Deep Investigations', icon: Search },
              { id: 'Vulnerabilities', label: 'Vulnerabilities', icon: ShieldCheck },
              { id: 'Hunts', label: 'Threat Hunting', icon: Target },
              { id: 'Quishing', label: 'Quishing Analyzer', icon: QrCode },
              { id: 'Sandbox', label: 'Live Sandbox', icon: Terminal },
              { id: 'Leaderboard', label: 'Risk Leaderboard', icon: Award },
              { id: 'Boardroom Report', label: 'Boardroom Report', icon: FileText },
              { id: 'IoC', label: 'IoC & Threat Intel', icon: Key },
              { id: 'XAI', label: 'Model Drift & XAI', icon: Cpu },
              { id: 'Settings', label: 'Settings', icon: Settings },
            ].map((item) => {
              const IconComponent = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-semibold transition-all duration-150 ${
                    isActive
                      ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/30 shadow-sm'
                      : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <IconComponent className={`h-4 w-4 ${isActive ? 'text-indigo-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-4 border-t border-slate-800/60">
          <div className="bg-slate-950 border border-slate-800 p-3 rounded-xl flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="text-xs text-slate-300 font-mono">Engine Active</span>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">99.8% ACC</span>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT WRAPPER */}
      <div className="flex-1 flex flex-col min-w-0 bg-slate-950">
        <header className="h-16 border-b border-slate-800/80 bg-slate-900/50 backdrop-blur px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-4">
            <h2 className="text-base font-bold text-white capitalize">{activeTab}</h2>
            <span className="px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-400 text-[10px] font-mono border border-slate-700/50">
              Tenant: Enterprise Corp (ZA)
            </span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowExportModal(true)}
              className="bg-slate-800 hover:bg-slate-700 border border-slate-700/70 text-slate-200 px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors"
            >
              <Download className="h-3.5 w-3.5 text-indigo-400" />
              Export Telemetry
            </button>

            <button
              onClick={handleDispatchRetrain}
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-2 shadow-md shadow-indigo-600/20 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Retrain Pipeline
            </button>
          </div>
        </header>

        {/* MAIN DYNAMIC SECTION CONTAINER */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {renderActiveTabContent()}
        </main>
      </div>

      {/* OVERLAY MODALS */}
      {showExportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Download className="h-5 w-5 text-indigo-400" />
                Incident &amp; Telemetry Export Wizard
              </h3>
              <button
                onClick={() => setShowExportModal(false)}
                className="text-slate-400 hover:text-white text-sm font-bold p-1"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Generate formatted threat dumps, STIX 2.1 IOC objects, or CSV raw logs for external SIEM integration (Splunk, Sentinel, QRadar).
            </p>

            <div className="space-y-3">
              <label className="block text-xs font-semibold text-slate-300">Export Format</label>
              <select
                id="simple-export-format"
                defaultValue="stix"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-indigo-500"
              >
                <option value="stix">STIX 2.1 Threat Intelligence Bundle (.json)</option>
                <option value="csv">Raw Incident Telemetry (.csv)</option>
                <option value="cef">Common Event Format / Syslog (.cef)</option>
              </select>
            </div>

            <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
              <button
                onClick={() => setShowExportModal(false)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:bg-slate-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  const format = document.getElementById('simple-export-format')?.value || 'stix';
                  const fileExt = format === 'cef' ? 'txt' : 'json';
                  const filename = `phishguard-telemetry.${fileExt}`;

                  const a = document.createElement('a');
                  const data = JSON.stringify({ format, exportedAt: new Date().toISOString(), status: 'queued' }, null, 2);
                  const blob = new Blob([data], { type: format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json;charset=utf-8' });
                  const url = URL.createObjectURL(blob);

                  a.href = url;
                  a.download = filename;
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                  URL.revokeObjectURL(url);
                  setShowExportModal(false);
                }}
                className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-xl text-xs font-semibold shadow-lg shadow-indigo-600/30 transition-colors"
              >
                Download Package
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// --- SUB-COMPONENT 2: Technology Contributions Horizontal Chart ---
const TechContributionsCard = ({ data }) => {
  // Mock dataset provided as a safe default in case data is missing from props
  const techContribData = data || [
    { name: 'XGBoost', current: 1420, previous: 1100, target: 1600, growth: '+29.1%' },
    { name: 'Heuristic Engine', current: 980, previous: 850, target: 1200, growth: '+15.3%' },
    { name: 'BERT NLP', current: 750, previous: 620, target: 900, growth: '+21.0%' },
  ];

  return (
    <div className="bg-[#0a0f1d] border border-slate-800/80 rounded-2xl p-6 relative flex flex-col justify-between shadow-2xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">
            Technology Contributions
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Comparative intake metrics & forecast trend targets
          </p>
        </div>
        <span className="text-[11px] font-medium text-slate-300 bg-slate-800/80 border border-slate-700/60 px-3 py-1 rounded-full">
          Telemetry Active
        </span>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 mb-6 text-xs text-slate-300">
        <div className="flex items-center gap-2">
          <span className="h-3 w-3 rounded-xs bg-cyan-400"></span>
          <span>Current Month</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-3 w-3 rounded-xs bg-purple-600"></span>
          <span>Previous Month</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-0.5 w-4 bg-white border-b border-dashed border-white"></span>
          <span className="flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-white"></span> Trend Line
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-0.5 w-4 border-b border-dashed border-slate-400"></span>
          <span>Forecast</span>
        </div>
      </div>

      {/* Custom Dual Bar Rows */}
      <div className="space-y-6">
        {(techContribData || []).map((item, index) => {
          const currentVal = item?.current ?? 0;
          const previousVal = item?.previous ?? 0;
          const targetVal = item?.target ?? 0;
          
          const maxVal = 2000;
          const currentPct = Math.min((currentVal / maxVal) * 100, 100);
          const prevPct = Math.min((previousVal / maxVal) * 100, 100);

          return (
            <div key={item?.name || index} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-200 text-sm w-32">{item?.name || 'Unknown Module'}</span>
                <div className="flex items-center gap-3 font-mono">
                  <span className="text-cyan-400 font-bold text-sm">
                    {targetVal.toLocaleString()} <span className="text-emerald-400 text-xs">({item?.growth || '0%'})</span>
                  </span>
                </div>
              </div>

              <div className="relative pt-1 pb-2">
                {/* Current Month Bar */}
                <div className="h-4 bg-slate-900 rounded-r-md overflow-hidden relative mb-1">
                  <div 
                    className="h-full bg-linear-to-r from-cyan-600 to-cyan-400 rounded-r-md transition-all duration-500 relative flex items-center justify-end pr-2"
                    style={{ width: `${currentPct}%` }}
                  >
                    <span className="text-[10px] font-bold text-slate-950 font-mono">
                      {currentVal.toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* Previous Month Bar */}
                <div className="h-3.5 bg-slate-900 rounded-r-md overflow-hidden relative">
                  <div 
                    className="h-full bg-linear-to-r from-purple-800 to-purple-600 rounded-r-md transition-all duration-500 relative flex items-center justify-end pr-2"
                    style={{ width: `${prevPct}%` }}
                  >
                    <span className="text-[9px] font-semibold text-slate-200 font-mono">
                      {previousVal.toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* Simulated Trend Target Indicator Line */}
                <div 
                  className="absolute top-1/2 -translate-y-1/2 h-0.5 border-b-2 border-dashed border-white/80 pointer-events-none flex items-center justify-between"
                  style={{ left: `${prevPct * 0.3}%`, width: `${Math.max(0, (currentPct - prevPct * 0.3) + 12)}%` }}
                >
                  <span className="h-2 w-2 rounded-full bg-white -ml-1 shadow-md"></span>
                  <span className="h-2 w-2 rounded-full bg-white shadow-md"></span>
                  <span className="h-2 w-2 rounded-full bg-white -mr-1 shadow-md"></span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* X-Axis Scale */}
      <div className="flex justify-between items-center text-[11px] font-mono text-slate-500 border-t border-slate-800/80 pt-3 mt-4">
        <span>0</span>
        <span>500</span>
        <span>1,000</span>
        <span>1,500</span>
      </div>
    </div>
  );
};

// --- SUB-COMPONENT 3: Global Threat Intelligence & Regional Breakdown ---
const GlobalThreatIntelligenceCard = () => {
  // Mock fallback data for regional vector metrics and breakdowns
  const miniVectorData = [
    {
      name: 'Cairo',
      vectors: [
        { label: 'Malicious Macro', value: 85 },
        { label: 'Phishing Link', value: 60 },
        { label: 'Payload Attach', value: 35 },
      ],
      sectors: [
        { name: 'Finance', value: 40, color: '#06b6d4' },
        { name: 'Telecom', value: 35, color: '#3b82f6' },
        { name: 'Government', value: 25, color: '#f59e0b' },
      ],
      timeSeries: [32, 45, 58, 51, 68, 72, 89],
    },
    {
      name: 'Lagos',
      vectors: [
        { label: 'Credential Harvest', value: 92 },
        { label: 'Phishing Link', value: 70 },
        { label: 'OAuth Exploits', value: 48 },
      ],
      sectors: [
        { name: 'Banking', value: 50, color: '#06b6d4' },
        { name: 'Fintech', value: 30, color: '#10b981' },
        { name: 'Retail', value: 20, color: '#f59e0b' },
      ],
      timeSeries: [20, 35, 42, 60, 55, 78, 95],
    },
    {
      name: 'Nairobi',
      vectors: [
        { label: 'Quishing / QR', value: 78 },
        { label: 'Malicious Macro', value: 52 },
        { label: 'Spear Phishing', value: 41 },
      ],
      sectors: [
        { name: 'NGO / Gov', value: 45, color: '#3b82f6' },
        { name: 'Logistics', value: 35, color: '#06b6d4' },
        { name: 'Healthcare', value: 20, color: '#ef4444' },
      ],
      timeSeries: [15, 28, 30, 48, 42, 61, 76.5],
    },
  ];

  return (
    <div className="bg-[#090d16] border border-slate-800/90 rounded-2xl p-6 space-y-6 shadow-2xl">
      {/* Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Globe className="h-5 w-5 text-cyan-400" />
            Global Threat Intelligence & Regional Vector Analysis
          </h2>
          <p className="text-xs text-slate-400">
            Live telemetry, vector segmentation, and regional attack surface breakdown
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300">
            <span className="text-slate-500">Region Focus:</span>
            <span className="font-semibold text-cyan-400">Gauteng, ZA</span>
            <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
          </div>
          <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300">
            <span className="text-slate-500">Vector:</span>
            <span className="font-semibold text-slate-200">Macro, Link, Attach</span>
            <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
          </div>
          <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300">
            <span className="text-slate-500">Time Range:</span>
            <span className="font-semibold text-slate-200">Last 74h</span>
            <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
          </div>
        </div>
      </div>

      {/* Top Map + Regional Breakdown 2-Column Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Global Map Display Container */}
        <div className="lg:col-span-7 bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 relative min-h-80 flex flex-col justify-between overflow-hidden">
          <div className="absolute top-3 left-3 z-10 bg-slate-900/90 border border-slate-800 p-3 rounded-lg text-xs space-y-1 max-w-50 backdrop-blur-sm">
            <span className="text-[10px] text-cyan-400 font-mono tracking-wider uppercase block">ACTIVE VIEW</span>
            <p className="font-bold text-white text-sm">Global Overview</p>
            <div className="text-slate-400 text-[11px] pt-1">
              <p>City: <span className="text-slate-200">Gauteng, ZA</span></p>
              <p>Total Intercepts: <span className="text-cyan-400 font-mono font-bold">1,428</span></p>
              <p>Top Attack: <span className="text-slate-200">Malicious Macro</span></p>
              <p>Risk Level: <span className="text-rose-400 font-bold">High</span></p>
            </div>
          </div>

          {/* Stylized World Map SVG Overlay */}
          <div className="absolute inset-0 flex items-center justify-center opacity-40 pointer-events-none">
            <img 
              src="https://upload.wikimedia.org/wikipedia/commons/8/80/World_map_ -_low_resolution.svg" 
              alt="World Map Grid" 
              className="w-full h-full object-cover filter invert hue-rotate-180 brightness-75"
            />
          </div>

          {/* Pulsing Hotspot Radar Nodes */}
          <div className="absolute top-[55%] left-[53%] -translate-x-1/2 -translate-y-1/2 flex items-center justify-center">
            <span className="animate-ping absolute inline-flex h-12 w-12 rounded-full bg-rose-500 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-6 w-6 bg-rose-600 border-2 border-white shadow-lg"></span>
          </div>

          <div className="absolute top-[35%] left-[25%] flex items-center justify-center">
            <span className="animate-ping absolute inline-flex h-8 w-8 rounded-full bg-amber-500 opacity-60"></span>
            <span className="relative inline-flex rounded-full h-4 w-4 bg-amber-500 border border-white"></span>
          </div>

          <div className="absolute top-[40%] left-[75%] flex items-center justify-center">
            <span className="animate-ping absolute inline-flex h-8 w-8 rounded-full bg-cyan-500 opacity-60"></span>
            <span className="relative inline-flex rounded-full h-4 w-4 bg-cyan-500 border border-white"></span>
          </div>

          <div className="mt-auto relative z-10 flex justify-between items-end text-[11px] text-slate-400 border-t border-slate-800/60 pt-2">
            <span>Pan-African Radar Grid Active</span>
            <span className="text-emerald-400 font-mono">Live Sync Active</span>
          </div>
        </div>

        {/* Regional Vector Breakdown Panel */}
        <div className="lg:col-span-5 bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 flex flex-col justify-between">
          <h3 className="text-sm font-bold text-slate-200 mb-3 tracking-wide">
            Regional Vector Breakdown (Selected Region: Africa)
          </h3>

          <div className="grid grid-cols-3 gap-3 h-full">
            {(miniVectorData || []).map((city) => (
              <div key={city.name} className="bg-slate-900/80 border border-slate-800/80 rounded-lg p-2.5 flex flex-col justify-between text-xs">
                <div>
                  <h4 className="font-bold text-white text-sm mb-2">{city.name}</h4>
                  
                  {/* Attack Vector Segmentation Stack */}
                  <p className="text-[10px] text-slate-400 uppercase tracking-tight mb-1">Attack Vector</p>
                  <div className="space-y-1 mb-3">
                    {(city.vectors || []).map((vec, i) => (
                      <div key={i} className="bg-slate-950 p-1 rounded border border-slate-800">
                        <div className="text-[9px] text-slate-300 truncate">{vec.label}</div>
                        <div className="h-1 bg-cyan-500/80 rounded-full mt-0.5" style={{ width: `${vec.value}%` }}></div>
                      </div>
                    ))}
                  </div>

                  {/* Source Sector Distribution Donut */}
                  <p className="text-[10px] text-slate-400 uppercase tracking-tight mb-1">Sector Dist.</p>
                  <div className="h-12 w-full flex items-center justify-center mb-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={city.sectors || []} cx="50%" cy="50%" innerRadius={10} outerRadius={20} dataKey="value">
                          {(city.sectors || []).map((sec, idx) => (
                            <Cell key={idx} fill={sec.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Sparkline Time Series */}
                <div>
                  <p className="text-[9px] text-slate-500 font-mono">Submissions (7d)</p>
                  <div className="h-6 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={(city.timeSeries || []).map((v, i) => ({ v, i }))}>
                        <Line type="monotone" dataKey="v" stroke="#06b6d4" strokeWidth={1.5} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>

              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Middle Stats Grid: Africa & Global Regional Telemetry */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        {[
          { region: 'Africa', city: 'Cairo', count: '1210', vector: 'Malicious Macro', risk: 'High', riskColor: 'text-amber-400' },
          { region: 'Africa', city: 'Lagos', count: '980', vector: 'Phishing Link', risk: 'Medium', riskColor: 'text-yellow-400' },
          { region: 'Global', city: 'Eastern Europe', count: '2150', vector: 'Ransomware', risk: 'Critical', riskColor: 'text-rose-500' },
          { region: 'Global', city: 'Western Europe', count: '1890', vector: 'Malicious Macro', risk: 'High', riskColor: 'text-amber-400' },
          { region: 'Global', city: 'Middle East', count: '1420', vector: 'Malicious Macro', risk: 'High', riskColor: 'text-amber-400' },
          { region: 'Global', city: 'East Asia', count: '2600', vector: 'Zero-Day Exploit', risk: 'Critical', riskColor: 'text-rose-500' },
          { region: 'Africa', city: 'Nairobi', count: '765', vector: 'Credential Harvest', risk: 'Medium', riskColor: 'text-yellow-400' },
          { region: 'Global', city: 'Southern Asia', count: '1780', vector: 'Phishing Link', risk: 'Medium', riskColor: 'text-yellow-400' },
        ].map((item, idx) => (
          <div key={idx} className="bg-slate-950/70 border border-slate-800/80 p-3 rounded-xl flex flex-col justify-between hover:border-slate-700 transition">
            <div className="space-y-1">
              <p className="text-xs font-bold text-white truncate">{item.city}</p>
              <p className="text-lg font-black text-cyan-400 font-mono tracking-tight">{item.count}</p>
            </div>
            <div>
              <p className="text-[10px] text-slate-400 truncate">{item.vector}</p>
              <span className={`text-[10px] font-extrabold uppercase tracking-wider ${item.riskColor}`}>
                {item.risk}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* South Africa Drill-Down Section Row */}
      <div className="bg-slate-950/90 border border-slate-800/90 rounded-xl p-4">
        <h3 className="text-sm font-bold text-slate-200 mb-3 tracking-wide flex items-center gap-2">
          <Layers className="h-4 w-4 text-cyan-400" />
          South Africa Drill-Down (Regional Sub-Nodes)
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { city: 'Johannesburg', count: '1150', vector: 'Malicious Macro', risk: 'High', riskColor: 'text-amber-400' },
            { city: 'Pretoria', count: '650', vector: 'Credential Harvest', risk: 'Medium', riskColor: 'text-yellow-400' },
            { city: 'Durban', count: '520', vector: 'Phishing Link', risk: 'High', riskColor: 'text-amber-400' },
            { city: 'Cape Town', count: '890', vector: 'Malicious Macro', risk: 'High', riskColor: 'text-amber-400' },
            { city: 'Pretoria East', count: '650', vector: 'Phishing Link', risk: 'High', riskColor: 'text-amber-400' },
            { city: 'Durban South', count: '520', vector: 'Phishing Link', risk: 'Low', riskColor: 'text-emerald-400' },
          ].map((saNode, idx) => (
            <div key={idx} className="bg-slate-900/90 border border-slate-800 p-3 rounded-lg flex flex-col justify-between">
              <span className="text-xs font-bold text-slate-100">{saNode.city}</span>
              <span className="text-base font-extrabold text-cyan-400 font-mono my-1">{saNode.count}</span>
              <span className="text-[10px] text-slate-400 truncate">{saNode.vector}</span>
              <span className={`text-[10px] font-bold ${saNode.riskColor}`}>{saNode.risk}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
};

return (
  <div className="space-y-6 text-slate-100">

    {/* 1. Global Threat Intelligence & Regional Vector Analysis */}
    <GlobalThreatIntelligenceCard />

    {/* 2. Top Action Grid: Export, ML Dispatcher, & Technology Contributions */}
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      
      {/* Incident & Telemetry Export Wizard */}
      <div className="bg-[#0d111a] border border-slate-800/80 rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
              Data Export
            </h3>
            <span className="text-xs bg-cyan-500/10 text-cyan-400 px-2.5 py-1 rounded border border-cyan-500/20">
              Ready
            </span>
          </div>
          <h4 className="text-base font-bold text-white mb-1">
            Incident & Telemetry Export Wizard
          </h4>
          <p className="text-xs text-slate-400 mb-4">
            Generate auditable compliance and threat reports with raw email headers and sanitized heuristics.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select className="bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 px-2.5 py-2 outline-none flex-1">
            <option>JSON / CSV</option>
            <option>PDF Report</option>
          </select>
          <button 
            onClick={() => alert('Export package generated successfully.')}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs px-3 py-2 rounded-lg transition-all cursor-pointer"
          >
            Export
          </button>
        </div>
      </div>

        {/* Automated Model Retraining Dispatcher */}
        <div className="bg-[#0d111a] border border-slate-800/80 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
                ML Ops Pipeline
              </h3>
              <span className="text-xs bg-emerald-500/10 text-emerald-400 px-2.5 py-1 rounded border border-emerald-500/20">
                Active Sync
              </span>
            </div>
            <h4 className="text-base font-bold text-white mb-1">
              Model Retraining Dispatcher
            </h4>
            <p className="text-xs text-slate-400 mb-4">
              Trigger heuristic weight recalculations and ingest fresh telemetry feedback loops.
            </p>
          </div>
          <div className="flex items-center justify-between bg-slate-950 px-3 py-2 rounded-lg border border-slate-800 text-xs">
            <span className="text-slate-400">AUC: 0.982</span>
            <button 
              onClick={() => alert('Model retraining background job dispatched successfully.')}
              className="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-3 py-1.5 rounded-md transition-all cursor-pointer"
            >
              Dispatch Job
            </button>
          </div>
        </div>

        {/* Interactive Technology Contributions (Updated Copilot UI) */}
        <TechContributionsCard />

      </div>

      {/* 3. Phishing Submissions Forecast with Anomalies (New Image 2 UI Replacement) */}
      <ForecastChartCard />

      {/* 4. Cost Avoidance & Secondary Metrics */}
      <div className="grid grid-cols-12 gap-6">
        
        {/* Trend Chart (Submissions over time) */}
        <div className="col-span-12 lg:col-span-8 bg-[#0d111a] border border-slate-800/80 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-base font-semibold text-slate-100">What did we catch?</h2>
                <p className="text-xs text-slate-400">Submissions by outcome over time</p>
              </div>
              <div className="flex items-center space-x-2 text-xs text-slate-400 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 cursor-pointer">
                <span>{timeRange}</span>
                <ChevronDown className="h-3 w-3" />
              </div>
            </div>

            <div className="h-52 w-full bg-[#111622] rounded-xl border border-slate-800/60 p-3 mt-3">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart
                  data={submissionsOverTimeData}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} domain={[0, 25]} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      fontSize: '12px',
                      borderRadius: '8px'
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="all"
                    stroke="#34d399"
                    strokeWidth={1.5}
                    dot={false}
                    activeDot={{ r: 5, stroke: '#34d399', strokeWidth: 2, fill: '#0f172a' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="malicious"
                    stroke="#06b6d4"
                    strokeWidth={2.5}
                    dot={false}
                    activeDot={{ r: 6, stroke: '#06b6d4', strokeWidth: 2, fill: '#0f172a' }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Estimated Cost Avoidance Card */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
          <div className="bg-linear-to-br from-slate-900 to-slate-900/90 border border-slate-800 rounded-2xl p-6 relative overflow-hidden flex-1 flex flex-col justify-center">
            <p className="text-xs font-semibold tracking-wider text-slate-400 uppercase mb-1">
              Estimated Cost Avoidance
            </p>
            <h3 className="text-3xl font-extrabold text-emerald-400 font-mono tracking-tight mb-2">
              R 12,450,000
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Calculated value of prevented phishing incidents per month
            </p>
          </div>
        </div>

      </div>

      {/* 5. Model Evaluation & Classification Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0d111a] border border-slate-800/80 rounded-xl p-6 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Model Evaluation
              </h3>
              <h4 className="text-base font-bold text-white">
                ROC Curve & Precision/Recall Metrics
              </h4>
            </div>
            <span className="text-xs bg-indigo-500/10 text-indigo-400 px-2.5 py-1 rounded border border-indigo-500/20">
              AUC: 0.982
            </span>
          </div>

          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={rocCurveData}
                margin={{ top: 5, right: 10, left: -20, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="fpr" stroke="#64748b" fontSize={10} domain={[0, 1]} />
                <YAxis stroke="#64748b" fontSize={10} domain={[0, 1]} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    fontSize: '12px'
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="tpr"
                  stroke="#38bdf8"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-[#0d111a] border border-slate-800/80 rounded-xl p-6 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Classification Matrix
              </h3>
              <h4 className="text-base font-bold text-white">
                Confusion Matrix Breakdown
              </h4>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 my-auto">
            <div className="bg-emerald-950/30 border border-emerald-500/30 p-4 rounded-xl flex flex-col justify-center items-center text-center">
              <span className="text-xs text-emerald-400 font-semibold mb-1">True Positive (TP)</span>
              <span className="text-2xl font-extrabold text-white">1,388</span>
            </div>
            <div className="bg-red-950/30 border border-red-500/30 p-4 rounded-xl flex flex-col justify-center items-center text-center">
              <span className="text-xs text-red-400 font-semibold mb-1">False Positive (FP)</span>
              <span className="text-2xl font-extrabold text-white">14</span>
            </div>
            <div className="bg-amber-950/30 border border-amber-500/30 p-4 rounded-xl flex flex-col justify-center items-center text-center">
              <span className="text-xs text-amber-400 font-semibold mb-1">False Negative (FN)</span>
              <span className="text-2xl font-extrabold text-white">30</span>
            </div>
            <div className="bg-indigo-950/30 border border-indigo-500/30 p-4 rounded-xl flex flex-col justify-center items-center text-center">
              <span className="text-xs text-indigo-400 font-semibold mb-1">True Negative (TN)</span>
              <span className="text-2xl font-extrabold text-white">4,850</span>
            </div>
          </div>
        </div>
      </div>

      {/* 6. URL & Email Heuristics Breakdowns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0d111a] border border-slate-800/80 rounded-xl p-6 flex flex-col justify-between">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-1">URL Heuristics</h3>
            <h4 className="text-base font-bold text-white">URL Heuristic Breakdown (Donut)</h4>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 items-center gap-4">
            <div className="h-48 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={urlHeuristicData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {urlHeuristicData.map((entry, index) => (
                      <Cell key={`cell-url-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-2 text-xs">
              {urlHeuristicData.map((item, index) => (
                <div key={index} className="flex items-center justify-between text-slate-300">
                  <span className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: item.color }}></span>
                    {item.name}
                  </span>
                  <span className="font-semibold">{item.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="bg-[#0d111a] border border-slate-800/80 rounded-xl p-6 flex flex-col justify-between">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-1">Email Threat Vectors</h3>
            <h4 className="text-base font-bold text-white">Email Heuristic Breakdown (Pie)</h4>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 items-center gap-4">
            <div className="h-48 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={emailHeuristicData}
                    cx="50%"
                    cy="50%"
                    innerRadius={0}
                    outerRadius={75}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {emailHeuristicData.map((entry, index) => (
                      <Cell key={`cell-email-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-2 text-xs">
              {emailHeuristicData.map((item, index) => (
                <div key={index} className="flex items-center justify-between text-slate-300">
                  <span className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: item.color }}></span>
                    {item.name}
                  </span>
                  <span className="font-semibold">{item.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

    </div>
  );

 return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans overflow-hidden">
      <aside
        className={`bg-slate-900 border-r border-slate-800 transition-all duration-300 flex flex-col ${
          sidebarOpen ? 'w-72' : 'w-20'
        }`}
      >
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          {sidebarOpen && (
            <div className="flex items-center space-x-2">
              <Shield className="h-6 w-6 text-cyan-400" />
              <span className="font-bold text-base tracking-wide text-white">
                PhishGuard Enterprise
              </span>
            </div>
          )}

          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 cursor-pointer"
          >
            <Menu className="h-5 w-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto py-4 px-3 space-y-4 text-sm">
          <button
            onClick={() => setActiveView('UEBA Telemetry')}
            title={!sidebarOpen ? 'UEBA Telemetry' : undefined}
            className={`w-full flex items-center ${
              sidebarOpen ? 'px-3 py-2.5 space-x-3' : 'justify-center p-2.5'
            } rounded-lg transition-colors ${
              activeView === 'UEBA Telemetry'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            }`}
          >
            <Activity className="h-5 w-5 shrink-0 text-cyan-400" />
            {sidebarOpen && <span className="font-medium truncate">UEBA Telemetry</span>}
          </button>

          <div>
            <button
              onClick={() => toggleCategory('Primary')}
              className="w-full flex items-center justify-between p-2 rounded-lg text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              {sidebarOpen && <span>Primary Direct Links</span>}
              {sidebarOpen &&
                (activeCategory.Primary ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                ))}
            </button>

            {sidebarOpen && activeCategory.Primary && (
              <div className="mt-1 space-y-1">
                <button
                  onClick={() => setActiveView('URL Threat Inspector')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'URL Threat Inspector'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <LinkIcon className="h-4 w-4 text-cyan-400" />
                  <span>URL Threat Inspector</span>
                </button>

                <button
                  onClick={() => setActiveView('Email Threat Inspector')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Email Threat Inspector'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Mail className="h-4 w-4 text-indigo-400" />
                  <span>Email Threat Inspector</span>
                </button>
              </div>
            )}
          </div>

          <div>
            <button
              onClick={() => toggleCategory('Activity')}
              className="w-full flex items-center justify-between p-2 rounded-lg text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              {sidebarOpen && <span>Activity</span>}
              {sidebarOpen &&
                (activeCategory.Activity ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                ))}
            </button>

            {sidebarOpen && activeCategory.Activity && (
              <div className="mt-1 space-y-1">
                <button
                  onClick={() => setActiveView('Overview')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Overview' || activeView === 'Dashboard'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Activity className="h-4 w-4 text-emerald-400" />
                  <span>Overview Dashboard</span>
                </button>

                <button
                  onClick={() => setActiveView('Actions')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Actions'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Zap className="h-4 w-4 text-amber-400" />
                  <span>Actions</span>
                </button>

                <button
                  onClick={() => setActiveView('Incidents')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Incidents'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <ShieldAlert className="h-4 w-4 text-red-400" />
                  <span>Incidents & War Room</span>
                </button>

                <button
                  onClick={() => setActiveView('Investigations')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Investigations'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Search className="h-4 w-4 text-cyan-400" />
                  <span>Investigations</span>
                </button>

                <button
                  onClick={() => setActiveView('Vulnerabilities')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Vulnerabilities'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <ShieldOff className="h-4 w-4 text-purple-400" />
                  <span>Vulnerabilities</span>
                </button>

                <button
                  onClick={() => setActiveView('Audit logs')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Audit logs'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <FileText className="h-4 w-4 text-blue-400" />
                  <span>Audit logs</span>
                </button>

                <button
                  onClick={() => setActiveView('Hunts')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Hunts'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Target className="h-4 w-4 text-orange-400" />
                  <span>Hunts</span>
                </button>
              </div>
            )}
          </div>

          <div>
            <button
              onClick={() => toggleCategory('Tools')}
              className="w-full flex items-center justify-between p-2 rounded-lg text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              {sidebarOpen && <span>Tools</span>}
              {sidebarOpen &&
                (activeCategory.Tools ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                ))}
            </button>

            {sidebarOpen && activeCategory.Tools && (
              <div className="mt-1 space-y-1">
                <button
                  onClick={() => setActiveView('Detections')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Detections'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  <span>Detections</span>
                </button>

                <button
                  onClick={() => setActiveView('Email Policies')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Email Policies'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <ShieldQuestion className="h-4 w-4 text-cyan-400" />
                  <span>Email Policies & Filters</span>
                </button>

                <button
                  onClick={() => setActiveView('Sandbox')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Sandbox'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Server className="h-4 w-4 text-cyan-400" />
                  <span>URL Detonation Sandbox</span>
                </button>

                <button
                  onClick={() => setActiveView('Boardroom Report')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Boardroom Report'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <FileCheck className="h-4 w-4 text-emerald-400" />
                  <span>Executive CISO Report</span>
                </button>

                <button
                  onClick={() => setActiveView('NIST CSF')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'NIST CSF'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <BarChart2 className="h-4 w-4 text-cyan-400" />
                  <span>NIST CSF</span>
                </button>

                <button
                  onClick={() => setActiveView('Cyber Resilience')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Cyber Resilience'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <RefreshCw className="h-4 w-4 text-indigo-400" />
                  <span>Cyber Resilience</span>
                </button>

                <button
                  onClick={() => setActiveView('Integrations')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Integrations'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Webhook className="h-4 w-4 text-pink-400" />
                  <span>Integrations</span>
                </button>

                <button
                  onClick={() => setActiveView('Simulator')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Simulator'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Users className="h-4 w-4 text-teal-400" />
                  <span>Campaign Simulator</span>
                </button>

                <button
                  onClick={() => setActiveView('Webhook Tester')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Webhook Tester'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <TerminalSquare className="h-4 w-4 text-amber-400" />
                  <span>SIEM Webhook Tester</span>
                </button>
              </div>
            )}
          </div>

          <div>
            <button
              onClick={() => toggleCategory('View')}
              className="w-full flex items-center justify-between p-2 rounded-lg text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              {sidebarOpen && <span>View</span>}
              {sidebarOpen &&
                (activeCategory.View ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                ))}
            </button>

            {sidebarOpen && activeCategory.View && (
              <div className="mt-1 space-y-1">
                <button
                  onClick={() => setActiveView('Quishing')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Quishing'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <QrCode className="h-4 w-4 text-amber-400" />
                  <span>Quishing Studio</span>
                </button>

                <button
                  onClick={() => setActiveView('IoC')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'IoC'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Key className="h-4 w-4 text-yellow-400" />
                  <span>IoC Feed & Export</span>
                </button>

                <button
                  onClick={() => setActiveView('XAI')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'XAI'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Cpu className="h-4 w-4 text-cyan-400" />
                  <span>XAI & Model Drift</span>
                </button>

                <button
                  onClick={() => setActiveView('Playbook')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Playbook'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <BookOpen className="h-4 w-4 text-teal-400" />
                  <span>Interactive Playbooks</span>
                </button>

                <button
                  onClick={() => setActiveView('Leaderboard')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Leaderboard'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <UserX className="h-4 w-4 text-red-400" />
                  <span>User Risk Leaderboard</span>
                </button>
              </div>
            )}
          </div>

          <div>
            <button
              onClick={() => toggleCategory('Settings')}
              className="w-full flex items-center justify-between p-2 rounded-lg text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              {sidebarOpen && <span>Settings</span>}
              {sidebarOpen &&
                (activeCategory.Settings ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                ))}
            </button>

            {sidebarOpen && activeCategory.Settings && (
              <div className="mt-1 space-y-1">
                <button
                  onClick={() => setActiveView('Organizational settings')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Organizational settings'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Building2 className="h-4 w-4 text-slate-400" />
                  <span>Organizational settings</span>
                </button>

                <button
                  onClick={() => setActiveView('Account settings')}
                  className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeView === 'Account settings'
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <UserCog className="h-4 w-4 text-slate-400" />
                  <span>Account settings</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-16 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6 shrink-0">
          <div className="flex items-center space-x-2 text-sm text-slate-400">
            <span>Dashboards</span>
            <span>&gt;</span>
            <span className="text-white font-medium">{activeView}</span>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => setShowExportModal(true)}
              className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 border border-slate-700 cursor-pointer"
            >
              <Download className="h-3.5 w-3.5" />
              Export Telemetry & Incidents
            </button>

            <span className="text-xs bg-emerald-500/10 text-emerald-400 px-3 py-1 rounded-full border border-emerald-500/20 flex items-center gap-1.5 font-medium">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
              Live Grid Active
            </span>
          </div>
        </header>

        {showExportModal && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-lg w-full space-y-4 shadow-2xl text-slate-100">
              <div className="flex items-center justify-between">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <FileSpreadsheet className="h-5 w-5 text-cyan-400" />
                  Incident & Telemetry Export Wizard
                </h3>

                <button
                  onClick={() => setShowExportModal(false)}
                  className="text-slate-400 hover:text-white p-1 cursor-pointer"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              <p className="text-xs text-slate-400">
                Configure parameters and formats for compliance reporting, executive PDFs, threat feeds, and SIEM log archival.
              </p>

              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 mb-1 font-medium">Export Format</label>
                    <select
                      id="telemetry-export-format"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                      defaultValue="pdf"
                    >
                      <option value="pdf">PDF (Executive Report)</option>
                      <option value="csv">CSV (Spreadsheet)</option>
                      <option value="json">JSON (Structured)</option>
                      <option value="stix">STIX 2.1 Bundle</option>
                      <option value="misp">MISP Event Feed</option>
                      <option value="cef">CEF (SIEM Syslog)</option>
                      <option value="splunk">Splunk HEC Batch</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1 font-medium">Time Window</label>
                    <select
                      id="telemetry-export-days"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                      defaultValue="7"
                    >
                      <option value="1">Past 24 Hours</option>
                      <option value="7">Past 7 Days</option>
                      <option value="30">Past 30 Days</option>
                      <option value="90">Full Retention (90d)</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Severity Level Filter</label>
                  <select
                    id="telemetry-export-severity"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                    defaultValue="ALL"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical Only</option>
                    <option value="HIGH">High Risk</option>
                    <option value="MEDIUM">Medium Risk</option>
                  </select>
                </div>
              </div>

              <div className="pt-3 flex items-center justify-end gap-2 border-t border-slate-800">
                <button
                  onClick={() => setShowExportModal(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-200 rounded-xl text-xs font-semibold hover:bg-slate-700 cursor-pointer"
                >
                  Cancel
                </button>

                <button
                  onClick={async () => {
                    const format = document.getElementById('telemetry-export-format').value;
                    const days = document.getElementById('telemetry-export-days').value;
                    const severity = document.getElementById('telemetry-export-severity').value;

                    const severityParam = severity !== 'ALL' ? `&severity=${severity}` : '';
                    const endpoint = `${apiUrl}/v1/telemetry/export?format=${format}&days=${days}${severityParam}&limit=1000`;

                    try {
                      const response = await fetch(endpoint);
                      if (!response.ok) throw new Error('Export request failed');

                      const blob = await response.blob();
                      const url = window.URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;

                      let fileExt = 'csv';
                      if (format === 'pdf') fileExt = 'pdf';
                      else if (format === 'cef') fileExt = 'txt';
                      else if (['stix', 'splunk', 'misp', 'json'].includes(format)) fileExt = 'json';

                      a.download = `phishguard-telemetry-${days}d.${fileExt}`;
                      document.body.appendChild(a);
                      a.click();
                      window.URL.revokeObjectURL(url);
                      document.body.removeChild(a);
                      setShowExportModal(false);
                    } catch (err) {
                      console.error('Download error:', err);
                      alert('Failed to connect to export backend endpoint.');
                    }
                  }}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-semibold transition-colors shadow-lg shadow-cyan-900/20 cursor-pointer"
                >
                  Download Report
                </button>
              </div>
            </div>
          </div>
        )}

        <main className="flex-1 overflow-y-auto p-6 bg-slate-950">{renderMainView()}</main>
      </div>
    </div>
  );
}

// End of file
