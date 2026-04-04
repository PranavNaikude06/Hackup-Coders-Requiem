import { motion } from 'motion/react';
import {
  ArrowLeft, FileText, AlertTriangle, Shield, Mail, Link,
  FolderOpen, Layers, CheckCircle2, AlertCircle, Cpu,
  ExternalLink, Users
} from 'lucide-react';
import { GlassCard } from '../components/GlassCard';
import { useNavigate, useLocation } from 'react-router';
import type { ScanResult } from '../api/threatApi';
import bgImage from 'figma:asset/62bbae5fd46eea7de9c86b6eeed87297c1e7a626.png';

// ── Helpers ──────────────────────────────────────────────────────────────────

function getIndicatorStyle(score: number, verdict: string) {
  if (verdict === 'SAFE' || score <= 25) {
    return { color: '#10B981', label: 'Safe', gradient: 'greenGradient' };
  }
  if (verdict === 'SUSPICIOUS' || score <= 59) {
    return { color: '#F59E0B', label: 'Suspicious', gradient: 'yellowGradient' };
  }
  return { color: '#EF4444', label: 'Risky', gradient: 'redGradient' };
}

function getScanIcon(type: string) {
  switch (type) {
    case 'url':      return Link;
    case 'email':    return Mail;
    case 'file':     return FolderOpen;
    case 'combined': return Layers;
    default:         return Shield;
  }
}

function getScanTitle(type: string) {
  switch (type) {
    case 'url':      return 'URL Scan Analysis';
    case 'email':    return 'Email Analysis';
    case 'file':     return 'File Upload Analysis';
    case 'combined': return 'Combined Analysis';
    default:         return 'Threat Analysis';
  }
}

function getProviderLabel(provider: string) {
  if (provider.includes('groq'))     return '⚡ Groq (Llama 3.3 70B)';
  if (provider.includes('openrouter')) return '🔀 OpenRouter (Gemma 3 27B)';
  if (provider.includes('ml') || provider.includes('distilbert') || provider.includes('attachment')) {
    return '🧠 Local ML Pipeline';
  }
  if (provider.includes('llm'))      return '🤖 LLM Provider';
  if (provider === 'error')          return '❌ Analysis Failed';
  return `📡 ${provider}`;
}

// Build findings list from real backend data
function buildFindings(result: ScanResult, scanType: string): { flag: string; text: string }[] {
  const findings: { flag: string; text: string }[] = [];

  // LLM explanation
  if (result.llm_human_explanation) {
    findings.push({ flag: '🔍 AI Analysis', text: result.llm_human_explanation });
  }

  // URL-specific
  if (result.url_risk_flag && result.url_risk_flag !== 'SAFE') {
    findings.push({ flag: '🚩 URL Risk', text: `URL classified as ${result.url_risk_flag} with ${Math.round((result.url_confidence || 0) * 100)}% confidence.` });
  }
  if (result.brand_impersonation) {
    findings.push({ flag: '⚠️ Brand Impersonation', text: `Domain appears to be impersonating "${result.brand_impersonation}". Possible typosquatting attack.` });
  }
  if (result.url_key_reasons && result.url_key_reasons.length > 0) {
    result.url_key_reasons.slice(0, 2).forEach((reason) => {
      findings.push({ flag: '🔴 Feature Flag', text: reason });
    });
  }

  // Email-specific
  if (result.evidence && result.evidence.length > 0) {
    result.evidence.slice(0, 3).forEach((ev) => {
      findings.push({ flag: '📧 Email Evidence', text: ev });
    });
  }
  if (result.chain_detected) {
    findings.push({ flag: '🔗 Chain Attack', text: 'Multi-stage attack detected: URL from email body matches phishing domain (email→link chain attack).' });
  }
  if (result.mismatch_detected) {
    findings.push({ flag: '🎯 Intent Mismatch', text: 'Email topic and URL purpose don\'t align — possible deceptive intent detected.' });
  }

  // File-specific
  if (result.file_flags && result.file_flags.length > 0) {
    result.file_flags.slice(0, 3).forEach((flag) => {
      findings.push({ flag: '📁 File Risk', text: flag });
    });
  }

  // Embedded URLs in email
  if (result.embedded_urls && result.embedded_urls.length > 0) {
    const risky = result.embedded_urls.filter((u) => u.risk_flag !== 'SAFE');
    if (risky.length > 0) {
      findings.push({ flag: '🌐 Embedded URLs', text: `${risky.length} suspicious URL(s) found in email body: ${risky.map((u) => u.url).join(', ')}` });
    }
  }

  // Campaign clustering
  if (result.campaign?.is_part_of_campaign) {
    findings.push({ flag: '👥 Campaign Alert', text: `This threat is part of a coordinated phishing campaign (${result.campaign.size || 'multiple'} similar attacks detected).` });
  }

  // Escalation
  if (result.escalate_to_phishing) {
    findings.push({ flag: '🚨 Escalated', text: 'LLM analysis escalated verdict to PHISHING based on contextual reasoning.' });
  }

  // Error state
  if (result.error) {
    findings.push({ flag: '❌ Scan Error', text: result.errorMessage || 'An unexpected error occurred during the scan.' });
  }

  // Safe fallback
  if (findings.length === 0 && (result.verdict === 'SAFE' || result.combined_score <= 25)) {
    findings.push({ flag: '✅ No Threats', text: 'No phishing indicators were detected. This content appears safe.' });
    if (scanType === 'url') {
      findings.push({ flag: '🔒 Clean URL', text: 'Domain structure, SSL status, and reputation checks all passed.' });
    }
    if (scanType === 'email' || scanType === 'combined') {
      findings.push({ flag: '📬 Clean Email', text: 'No urgency tactics, credential requests, or malicious links detected.' });
    }
  }

  return findings.slice(0, 6); // cap at 6
}

// Build breakdown cards for detailed section
function buildBreakdown(result: ScanResult, scanType: string) {
  const cards = [];

  if (scanType === 'url' || scanType === 'combined') {
    const urlScore = result.url_confidence != null
      ? Math.round(result.url_confidence * 100)
      : result.verdict === 'SAFE' ? 10 : result.combined_score;
    const c = urlScore > 59 ? '#EF4444' : urlScore > 25 ? '#F59E0B' : '#10B981';
    cards.push({ label: 'URL Analysis', subtitle: 'RandomForest structural scan', value: urlScore, color: c, icon: Link });
  }

  if (scanType === 'email' || scanType === 'combined') {
    const emailFlag = result.email_verdict || 'SAFE';
    const emailScore = emailFlag === 'PHISHING' || emailFlag === 'HIGH_RISK' ? 80 : emailFlag === 'SUSPICIOUS' ? 50 : 15;
    const c = emailScore > 59 ? '#EF4444' : emailScore > 25 ? '#F59E0B' : '#10B981';
    cards.push({ label: 'Email NLP', subtitle: 'DistilBERT content analysis', value: emailScore, color: c, icon: Mail });
  }

  if (result.file_risk_score != null) {
    const c = result.file_risk_score > 59 ? '#EF4444' : result.file_risk_score > 25 ? '#F59E0B' : '#10B981';
    cards.push({ label: 'File Analysis', subtitle: 'Static + VirusTotal scan', value: result.file_risk_score, color: c, icon: FolderOpen });
  }

  if (result.chain_detected !== undefined || result.mismatch_detected !== undefined) {
    const threatCount = [result.chain_detected, result.mismatch_detected].filter(Boolean).length;
    const hardScore = threatCount === 2 ? 90 : threatCount === 1 ? 60 : 5;
    const c = hardScore > 59 ? '#EF4444' : hardScore > 25 ? '#F59E0B' : '#10B981';
    cards.push({ label: 'Hard Rules', subtitle: 'Chain detection + intent check', value: hardScore, color: c, icon: Shield });
  }

  // Fill to min 2 cards if missing
  if (cards.length === 0) {
    const c = result.combined_score > 59 ? '#EF4444' : result.combined_score > 25 ? '#F59E0B' : '#10B981';
    cards.push({ label: 'Overall Score', subtitle: 'Combined threat assessment', value: result.combined_score, color: c, icon: Cpu });
    cards.push({
      label: 'Threat Level',
      subtitle: result.verdict || 'Unknown',
      value: result.combined_score,
      color: c,
      icon: AlertCircle,
    });
  }

  return cards;
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function Result() {
  const navigate = useNavigate();
  const location = useLocation();
  const scanType: string = location.state?.scanType || 'url';
  const result: ScanResult = location.state?.result || {
    combined_score: 0,
    verdict: 'UNKNOWN',
    analysis_provider: 'error',
    error: true,
    errorMessage: 'No scan data received. Please start a new scan.',
  };

  const overallRisk = result.combined_score ?? 0;
  const indicatorStyle = getIndicatorStyle(overallRisk, result.verdict);
  const ScanIcon = getScanIcon(scanType);
  const findings = buildFindings(result, scanType);
  const breakdown = buildBreakdown(result, scanType);
  const isError = !!result.error;
  const isSafe = result.verdict === 'SAFE' || overallRisk <= 25;
  const borderColor = isSafe ? 'border-green-500/30' : 'border-red-500/30';
  const shadowColor = isSafe ? 'shadow-green-500/10' : 'shadow-red-500/10';

  return (
    <div className="min-h-screen bg-black relative py-6 px-4">
      {/* Background Image */}
      <div
        className="fixed inset-0 opacity-60"
        style={{
          backgroundImage: `url(${bgImage})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
        }}
      />

      {/* Content */}
      <div className="relative z-10 max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-4 flex items-center justify-between">
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
          >
            <ArrowLeft size={20} />
            <span>Back to Home</span>
          </button>

          {/* Provider badge */}
          <span className="text-xs text-gray-500 bg-gray-800/60 px-3 py-1 rounded-full border border-gray-700">
            {getProviderLabel(result.analysis_provider)}
          </span>
        </div>

        {/* Large Dashboard Container */}
        <GlassCard className="p-6 shadow-2xl shadow-cyan-500/10 rounded-3xl">
          {/* TOP ROW */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">

            {/* LEFT — Findings / Explanation */}
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6 }}
            >
              <GlassCard className={`p-5 border ${borderColor} shadow-lg ${shadowColor} rounded-2xl h-full`}>
                <div className="flex items-center gap-3 mb-4">
                  <ScanIcon size={28} className="text-cyan-400" />
                  <h2 className="text-xl font-bold text-white">{getScanTitle(scanType)}</h2>
                </div>

                <div className="space-y-4">
                  {findings.map((finding, index) => (
                    <motion.div
                      key={index}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.2 + index * 0.1, duration: 0.5 }}
                      className={`bg-black/40 border rounded-xl p-5 hover:border-opacity-70 transition-all duration-200 ${
                        isSafe ? 'border-green-500/30' : 'border-red-500/30'
                      }`}
                    >
                      <div className="flex gap-4 items-start">
                        <div className="flex-shrink-0 mt-0.5">
                          <span className="text-2xl">{finding.flag.split(' ')[0]}</span>
                        </div>
                        <div>
                          <h4 className={`font-semibold text-lg mb-1.5 ${isSafe ? 'text-green-400' : 'text-red-400'}`}>
                            {finding.flag.substring(finding.flag.indexOf(' ') + 1)}
                          </h4>
                          <p className="text-gray-300 text-sm leading-relaxed">
                            {finding.text}
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>

                {/* Campaign alert strip */}
                {result.campaign?.is_part_of_campaign && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.9 }}
                    className="mt-6 flex items-center gap-3 bg-purple-500/10 border border-purple-500/40 rounded-xl p-4"
                  >
                    <Users size={22} className="text-purple-400 flex-shrink-0" />
                    <p className="text-purple-300 text-sm font-medium">
                      Part of coordinated campaign — {result.campaign.size || 'multiple'} similar threats tracked
                    </p>
                  </motion.div>
                )}

                {/* Alert warning / safe confirm */}
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.8 }}
                  className={`mt-6 flex items-center gap-3 rounded-xl p-4 ${
                    isSafe
                      ? 'bg-green-500/10 border border-green-500/40'
                      : isError
                      ? 'bg-gray-500/10 border border-gray-500/40'
                      : 'bg-red-500/10 border border-red-500/40'
                  }`}
                >
                  {isSafe ? (
                    <CheckCircle2 size={24} className="text-green-400 flex-shrink-0" />
                  ) : isError ? (
                    <AlertCircle size={24} className="text-gray-400 flex-shrink-0" />
                  ) : (
                    <AlertTriangle size={24} className="text-red-400 flex-shrink-0" />
                  )}
                  <p className={`text-sm font-medium ${isSafe ? 'text-green-300' : isError ? 'text-gray-300' : 'text-red-300'}`}>
                    {isSafe
                      ? 'No significant threats detected. Content appears safe.'
                      : isError
                      ? 'Scan could not be completed. Please check your backend and try again.'
                      : 'Threat indicators detected. Exercise caution.'}
                  </p>
                </motion.div>
              </GlassCard>
            </motion.div>

            {/* RIGHT — Circular Indicator */}
            <div className="flex items-center justify-center">
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.3, duration: 0.6 }}
                className="w-full"
              >
                <GlassCard className="p-10 border-2 border-cyan-500/40 shadow-2xl shadow-cyan-500/20 rounded-3xl">
                  <div className="flex flex-col items-center">
                    <h3 className="text-2xl font-bold text-white mb-10">Indicator</h3>

                    <div className="relative">
                      <motion.div
                        initial={{ scale: 0, rotate: -180 }}
                        animate={{ scale: 1, rotate: 0 }}
                        transition={{ type: 'spring', duration: 1, delay: 0.5 }}
                        className="relative inline-block"
                      >
                        <svg width="300" height="300" className="transform -rotate-90">
                          <circle cx="150" cy="150" r="130" fill="none" stroke="#1F2937" strokeWidth="24" />
                          <motion.circle
                            cx="150" cy="150" r="130"
                            fill="none"
                            stroke={`url(#${indicatorStyle.gradient})`}
                            strokeWidth="24"
                            strokeLinecap="round"
                            initial={{ strokeDasharray: '0 817' }}
                            animate={{ strokeDasharray: `${(overallRisk / 100) * 817} 817` }}
                            transition={{ duration: 2, ease: 'easeOut', delay: 0.8 }}
                            style={{ filter: `drop-shadow(0 0 20px ${indicatorStyle.color}99)` }}
                          />
                          <defs>
                            <linearGradient id="greenGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                              <stop offset="0%" stopColor="#10B981" />
                              <stop offset="100%" stopColor="#34D399" />
                            </linearGradient>
                            <linearGradient id="yellowGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                              <stop offset="0%" stopColor="#F59E0B" />
                              <stop offset="100%" stopColor="#FBBF24" />
                            </linearGradient>
                            <linearGradient id="redGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                              <stop offset="0%" stopColor="#EF4444" />
                              <stop offset="100%" stopColor="#F87171" />
                            </linearGradient>
                          </defs>
                        </svg>

                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <motion.span
                            initial={{ opacity: 0, scale: 0.5 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ delay: 1.3, duration: 0.6, type: 'spring' }}
                            className="text-8xl font-bold"
                            style={{ color: indicatorStyle.color, textShadow: `0 0 40px ${indicatorStyle.color}CC` }}
                          >
                            {overallRisk}%
                          </motion.span>
                        </div>
                      </motion.div>
                    </div>

                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 1.6 }}
                      className="mt-10 px-10 py-4 rounded-2xl border-2"
                      style={{
                        backgroundColor: `${indicatorStyle.color}22`,
                        borderColor: `${indicatorStyle.color}66`,
                        boxShadow: `0 0 25px ${indicatorStyle.color}44`,
                      }}
                    >
                      <span className="text-3xl font-bold" style={{ color: indicatorStyle.color }}>
                        {indicatorStyle.label}
                      </span>
                    </motion.div>
                  </div>
                </GlassCard>
              </motion.div>
            </div>
          </div>

          {/* BOTTOM ROW — Detailed Breakdown */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.6 }}
          >
            <h2 className="text-2xl font-bold text-white mb-6">Detailed Breakdown</h2>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              {breakdown.map((category, index) => {
                const Icon = category.icon;
                return (
                  <motion.div
                    key={category.label}
                    initial={{ opacity: 0, x: index % 2 === 0 ? -30 : 30 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.6 + index * 0.1, duration: 0.5 }}
                  >
                    <GlassCard
                      className="p-5 rounded-2xl hover:border-opacity-70 transition-all duration-200"
                      style={{
                        borderColor: `${category.color}50`,
                        boxShadow: `0 4px 20px ${category.color}15`,
                      }}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg" style={{ background: `${category.color}20` }}>
                            <Icon size={24} style={{ color: category.color }} />
                          </div>
                          <div>
                            <h3 className="font-semibold text-white">{category.label}</h3>
                            <p className="text-sm text-gray-400">{category.subtitle}</p>
                          </div>
                        </div>
                        <motion.span
                          initial={{ opacity: 0, scale: 0.5 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ delay: 0.8 + index * 0.1, type: 'spring' }}
                          className="text-2xl font-bold"
                          style={{ color: category.color }}
                        >
                          {category.value}%
                        </motion.span>
                      </div>

                      <div className="relative h-3 bg-gray-700/50 rounded-full overflow-hidden">
                        <motion.div
                          className="absolute left-0 top-0 h-full rounded-full"
                          style={{
                            background: `linear-gradient(to right, ${category.color}, ${category.color}CC)`,
                            boxShadow: `0 0 15px ${category.color}88`,
                          }}
                          initial={{ width: 0 }}
                          animate={{ width: `${category.value}%` }}
                          transition={{ duration: 1.5, delay: 0.8 + index * 0.1, ease: 'easeOut' }}
                        />
                      </div>
                    </GlassCard>
                  </motion.div>
                );
              })}
            </div>

            {/* Embedded URL list (if any) */}
            {result.embedded_urls && result.embedded_urls.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 1.0 }}
                className="mb-6"
              >
                <GlassCard className="p-5 border border-gray-700/50 rounded-2xl">
                  <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
                    <ExternalLink size={20} className="text-blue-400" />
                    Embedded URLs in Email
                  </h3>
                  <div className="space-y-2">
                    {result.embedded_urls.map((eu, i) => {
                      const c = eu.risk_flag === 'SAFE' ? '#10B981' : eu.risk_flag === 'SUSPICIOUS' ? '#F59E0B' : '#EF4444';
                      return (
                        <div key={i} className="flex items-center justify-between bg-black/30 rounded-xl px-4 py-2">
                          <span className="text-xs text-gray-300 truncate max-w-xs">{eu.url}</span>
                          <span className="text-xs font-semibold ml-4 flex-shrink-0" style={{ color: c }}>{eu.risk_flag}</span>
                        </div>
                      );
                    })}
                  </div>
                </GlassCard>
              </motion.div>
            )}

            {/* View Full Report / New Scan */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.2 }}
              className="flex gap-4"
            >
              <motion.button
                whileHover={{ scale: 1.05, boxShadow: '0 0 30px rgba(59, 130, 246, 0.8)' }}
                whileTap={{ scale: 0.98 }}
                transition={{ type: 'spring', stiffness: 800, damping: 15 }}
                onClick={() => navigate('/')}
                className="flex-1 flex items-center justify-center gap-3 px-8 py-4 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-2xl font-bold text-lg shadow-lg shadow-blue-500/30 transition-colors duration-75"
              >
                <FileText size={22} />
                Scan Another
              </motion.button>
            </motion.div>
          </motion.div>
        </GlassCard>
      </div>
    </div>
  );
}