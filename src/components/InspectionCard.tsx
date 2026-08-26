import React from 'react';
import { InspectionResult } from '../hooks/usePhishingInspector';

interface InspectionCardProps {
  result: InspectionResult;
}

export const InspectionCard: React.FC<InspectionCardProps> = ({ result }) => {
  const { url, prediction, is_phishing, risk_score, risk_level, model_score, details } = result;

  // Dynamic color configuration based on risk severity
  const getSeverityStyles = () => {
    switch (risk_level) {
      case 'CRITICAL':
        return {
          bg: 'bg-red-500/10',
          border: 'border-red-500/30',
          badge: 'bg-red-500 text-white',
          text: 'text-red-400',
          bar: 'bg-red-500',
        };
      case 'HIGH':
        return {
          bg: 'bg-orange-500/10',
          border: 'border-orange-500/30',
          badge: 'bg-orange-500 text-white',
          text: 'text-orange-400',
          bar: 'bg-orange-500',
        };
      case 'MEDIUM':
        return {
          bg: 'bg-yellow-500/10',
          border: 'border-yellow-500/30',
          badge: 'bg-yellow-500 text-black',
          text: 'text-yellow-400',
          bar: 'bg-yellow-500',
        };
      case 'LOW':
      default:
        return {
          bg: 'bg-emerald-500/10',
          border: 'border-emerald-500/30',
          badge: 'bg-emerald-500 text-white',
          text: 'text-emerald-400',
          bar: 'bg-emerald-500',
        };
    }
  };

  const styles = getSeverityStyles();
  const confidencePercent = model_score ? Math.round(model_score * 100) : 0;

  return (
    <div className={w-full rounded-xl border \ \ p-6 shadow-lg backdrop-blur-md transition-all duration-300}>
      {/* Header section with URL and Verdict Badge */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="overflow-hidden">
          <p className="text-xs uppercase tracking-wider text-slate-400">Target Domain</p>
          <h3 className="truncate text-lg font-bold text-white" title={url}>
            {url}
          </h3>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <span className={ounded-full px-3 py-1 text-xs font-black uppercase tracking-wider \}>
            {risk_level}
          </span>
          <span
            className={ounded-full border px-3 py-1 text-xs font-semibold \}
          >
            {prediction}
          </span>
        </div>
      </div>

      {/* Metrics Section: Risk Score & ML Confidence */}
      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/* Risk Score Gauge */}
        <div className="rounded-lg bg-slate-900/60 p-4 border border-slate-800">
          <div className="flex justify-between items-center mb-2">
            <span className="text-sm text-slate-300 font-medium">Composite Risk Score</span>
            <span className={	ext-xl font-bold \}>{risk_score.toFixed(1)} / 100</span>
          </div>
          <div className="h-2.5 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className={h-full transition-all duration-500 \}
              style={{ width: \% }}
            />
          </div>
        </div>

        {/* Machine Learning Model Probability */}
        <div className="rounded-lg bg-slate-900/60 p-4 border border-slate-800">
          <div className="flex justify-between items-center mb-2">
            <span className="text-sm text-slate-300 font-medium">ML Probability Score</span>
            <span className="text-xl font-bold text-slate-100">{confidencePercent}%</span>
          </div>
          <div className="h-2.5 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className="h-full bg-indigo-500 transition-all duration-500"
              style={{ width: \% }}
            />
          </div>
        </div>
      </div>

      {/* Optional Heuristic Breakdowns / Details List */}
      {details && Object.keys(details).length > 0 && (
        <div className="mt-6 rounded-lg bg-slate-900/40 p-4 border border-slate-800/80">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
            Triggered Heuristics & Features
          </h4>
          <div className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-3">
            {Object.entries(details).map(([key, val]) => (
              <div key={key} className="flex items-center justify-between rounded bg-slate-800/50 px-2.5 py-1.5">
                <span className="truncate text-slate-300 text-xs">{key.replace(/_/g, ' ')}</span>
                <span className="font-mono text-xs font-bold text-slate-200">
                  {typeof val === 'boolean' ? (val ? 'Yes' : 'No') : String(val)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
