/**
 * threatApi.ts — ThreatLens API client
 * Connects to FastAPI backend at /api/* (proxied to localhost:8000 in dev).
 * Normalises all four scan-type responses into a single ScanResult shape.
 */
const BASE = import.meta.env.VITE_API_URL || '/api';
// ─── Normalised result shape consumed by Result.tsx ───────────────────────────

export interface EmbeddedUrl {
  url: string;
  risk_flag: string;
  confidence?: number;
}

export interface CampaignInfo {
  is_part_of_campaign: boolean;
  size?: number;
  label?: string;
  campaign_id?: string;
}

export interface ScanResult {
  // Core verdict
  combined_score: number;           // 0–100
  verdict: 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'UNKNOWN';
  analysis_provider: string;

  // URL layer
  url_risk_flag?: string;
  url_confidence?: number;
  brand_impersonation?: string | null;
  url_key_reasons?: string[];

  // Email layer
  email_verdict?: string;
  evidence?: string[];
  chain_detected?: boolean;
  mismatch_detected?: boolean;
  embedded_urls?: EmbeddedUrl[];

  // LLM explanation
  llm_human_explanation?: string;
  escalate_to_phishing?: boolean;

  // Campaign clustering
  campaign?: CampaignInfo;

  // File attachment
  file_verdict?: string;
  file_risk_score?: number;
  file_flags?: string[];

  // Error
  error?: boolean;
  errorMessage?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function riskToScore(flag: string): number {
  if (flag === 'PHISHING' || flag === 'HIGH_RISK') return 75;
  if (flag === 'SUSPICIOUS') return 50;
  return 15;
}

function verdictFromFlag(flag: string): ScanResult['verdict'] {
  if (flag === 'PHISHING' || flag === 'HIGH_RISK') return 'PHISHING';
  if (flag === 'SUSPICIOUS') return 'SUSPICIOUS';
  return 'SAFE';
}

// ─── URL Scan ─────────────────────────────────────────────────────────────────

export async function scanUrl(url: string): Promise<ScanResult> {
  const res = await fetch(`${BASE}/analyze/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  if (!res.ok) {
    const detail = await res.text();
    return { combined_score: 0, verdict: 'UNKNOWN', analysis_provider: 'error', error: true, errorMessage: detail };
  }

  const data = await res.json();
  const model = data.model_analysis || {};
  const risk_flag: string = model.risk_flag || 'SAFE';
  const confidence: number = model.confidence || 0;
  const lookalike = data.features?._lookalike || {};
  const reasons: string[] = model.humanized_verdict?.key_reasons || [];

  const score = Math.min(100, Math.round(confidence * 100));

  return {
    combined_score: score,
    verdict: verdictFromFlag(risk_flag),
    analysis_provider: 'ml_pipeline',
    url_risk_flag: risk_flag,
    url_confidence: confidence,
    brand_impersonation: lookalike.is_lookalike ? lookalike.matched_brand : null,
    url_key_reasons: reasons,
    llm_human_explanation: model.humanized_verdict?.summary || '',
  };
}

// ─── Email Scan ───────────────────────────────────────────────────────────────

export async function scanEmail(emailText: string): Promise<ScanResult> {
  const res = await fetch(`${BASE}/analyze/email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email_text: emailText }),
  });

  if (!res.ok) {
    const detail = await res.text();
    return { combined_score: 0, verdict: 'UNKNOWN', analysis_provider: 'error', error: true, errorMessage: detail };
  }

  const data = await res.json();
  const ea = data.email_analysis || {};
  const verdict = ea.verdict || 'SAFE';
  const score = riskToScore(verdict);

  return {
    combined_score: score,
    verdict: verdictFromFlag(verdict),
    analysis_provider: 'distilbert',
    email_verdict: verdict,
    evidence: ea.evidence || [],
    embedded_urls: data.embedded_urls_found || [],
    llm_human_explanation: ea.explanation || '',
  };
}

// ─── File Attachment Scan ─────────────────────────────────────────────────────

export async function scanFile(file: File): Promise<ScanResult> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${BASE}/analyze/attachment`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const detail = await res.text();
    return { combined_score: 0, verdict: 'UNKNOWN', analysis_provider: 'error', error: true, errorMessage: detail };
  }

  const data = await res.json();
  // Backend returns 'attachment_score' and 'findings'
  const risk_score: number = data.attachment_score ?? data.risk_score ?? 0;
  const verdict_raw: string = data.verdict || 'SAFE';
  const findings: string[] = data.findings || data.flags || data.risk_factors || [];

  return {
    combined_score: risk_score,
    verdict: verdictFromFlag(verdict_raw),
    analysis_provider: 'attachment_analyzer',
    file_verdict: verdict_raw,
    file_risk_score: risk_score,
    file_flags: findings,
    llm_human_explanation: data.summary || data.explanation || '',
    evidence: findings,
  };
}

// ─── Combined Scan (SSE Streaming) ────────────────────────────────────────────

export type SSEProgressCallback = (stage: string, payload: Record<string, unknown>) => void;

export async function scanCombined(
  url: string,
  emailText: string,
  onProgress: SSEProgressCallback
): Promise<ScanResult> {
  return new Promise((resolve) => {
    let partialResult: Partial<ScanResult> = {
      analysis_provider: 'stream',
    };

    const ctrl = new AbortController();

    fetch(`${BASE}/analyze/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, email_text: emailText }),
      signal: ctrl.signal,
    }).then(async (res) => {
      if (!res.ok || !res.body) {
        resolve({
          combined_score: 0,
          verdict: 'UNKNOWN',
          analysis_provider: 'error',
          error: true,
          errorMessage: `Server error ${res.status}`,
        });
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // Parse SSE events from buffer
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        let currentEvent = '';
        let currentData = '';

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim();
          } else if (line.startsWith('data: ')) {
            currentData = line.slice(6).trim();
          } else if (line === '' && currentEvent && currentData) {
            // Dispatch event
            try {
              const payload = JSON.parse(currentData) as Record<string, unknown>;
              onProgress(currentEvent, payload);

              if (currentEvent === 'url_scan') {
                partialResult.url_risk_flag = payload.risk_flag as string;
                partialResult.url_confidence = payload.confidence as number;
                partialResult.brand_impersonation = (payload.brand_impersonation as string) || null;
                partialResult.url_key_reasons = (payload.key_reasons as string[]) || [];
              } else if (currentEvent === 'email_scan') {
                partialResult.email_verdict = payload.email_verdict as string;
                partialResult.evidence = (payload.evidence as string[]) || [];
                partialResult.chain_detected = payload.chain_detected as boolean;
                partialResult.mismatch_detected = payload.mismatch_detected as boolean;
                partialResult.embedded_urls = (payload.embedded_urls as EmbeddedUrl[]) || [];
              } else if (currentEvent === 'final') {
                partialResult.combined_score = Math.max(0, Math.min(100, (payload.combined_score as number) || 0));
                partialResult.verdict = (payload.verdict as ScanResult['verdict']) || 'SUSPICIOUS';
                partialResult.analysis_provider = (payload.analysis_provider as string) || 'llm';
                partialResult.llm_human_explanation = (payload.llm_human_explanation as string) || '';
                partialResult.escalate_to_phishing = payload.escalate_to_phishing as boolean;
                if (payload.campaign) {
                  partialResult.campaign = payload.campaign as CampaignInfo;
                }
              } else if (currentEvent === 'done') {
                ctrl.abort();
                resolve({
                  combined_score: partialResult.combined_score ?? 0,
                  verdict: partialResult.verdict ?? 'UNKNOWN',
                  analysis_provider: partialResult.analysis_provider ?? 'stream',
                  ...partialResult,
                });
                return;
              } else if (currentEvent === 'error') {
                resolve({
                  combined_score: 0,
                  verdict: 'UNKNOWN',
                  analysis_provider: 'error',
                  error: true,
                  errorMessage: (payload.message as string) || 'Unknown stream error',
                });
                return;
              }
            } catch {
              // ignore malformed SSE line
            }
            currentEvent = '';
            currentData = '';
          }
        }
      }

      // Stream ended without 'done' event — return what we have
      resolve({
        combined_score: partialResult.combined_score ?? 0,
        verdict: partialResult.verdict ?? 'UNKNOWN',
        analysis_provider: partialResult.analysis_provider ?? 'stream',
        ...partialResult,
      });
    }).catch((err) => {
      if ((err as Error).name !== 'AbortError') {
        resolve({
          combined_score: 0,
          verdict: 'UNKNOWN',
          analysis_provider: 'error',
          error: true,
          errorMessage: (err as Error).message || 'Network error',
        });
      }
    });
  });
}
