import { useState } from 'react';

export interface InspectionResult {
  status: string;
  url: string;
  prediction: 'PHISHING' | 'LEGITIMATE';
  is_phishing: boolean;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  model_score?: number;
  details?: Record<string, unknown>;
}

export const usePhishingInspector = (apiBaseUrl = '') => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InspectionResult | null>(null);

  const inspectUrl = async (urlToInspect: string) => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(${apiBaseUrl}/api/v1/inspect, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: urlToInspect }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to analyze URL');
      }

      setResult(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred');
      }
    } finally {
      setLoading(false);
    }
  };

  return { inspectUrl, loading, error, result };
};
