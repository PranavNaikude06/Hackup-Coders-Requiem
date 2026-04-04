import { useState, useEffect, useRef } from 'react';
import { motion } from 'motion/react';
import { Clock, Shield, Database, Cpu, CheckCircle2, AlertCircle } from 'lucide-react';
import { GlassCard } from '../components/GlassCard';
import { useNavigate, useLocation } from 'react-router';
import { scanUrl, scanEmail, scanFile, scanCombined } from '../api/threatApi';
import type { ScanResult } from '../api/threatApi';
import type { InputData } from '../components/InputSection';

import frame1 from 'figma:asset/ccb5b48d2cdfe65061355ec37aed184e10e39a7c.png';
import frame2 from 'figma:asset/1bf6a90ed8d2eede294bb3ccc5e175a2ae636769.png';
import frame3 from 'figma:asset/fb333ae444fd9c2a5453bfe99c486213797e1b9e.png';
import frame4 from 'figma:asset/1562175593c93556fd173cd69b9dc70c84cb3d4b.png';
import frame5 from 'figma:asset/31f8142d89d0085458decfead08ec602522b5c0e.png';
import frame6 from 'figma:asset/a56857c76a19d81d640f9714682ab68f00291681.png';
import frame7 from 'figma:asset/6dcbff71462744ce89cca7749c9c9f72d1d3d1a6.png';
import frame8 from 'figma:asset/9cc5b4b398e9d16d6a45192f92592d9156d622e1.png';
import frame9 from 'figma:asset/090e93dde7c27b14e637a947e2df88151897d6ca.png';
import frame10 from 'figma:asset/70c1da95aa7366c0bc4eea6e9ffe96f7ffa81b95.png';
import frame11 from 'figma:asset/8c34f1799b83046edb4095b4189cf5091ee6829e.png';
import frame12 from 'figma:asset/0132ca56b80d25c6277ce8b6ea0cf529810f8b2c.png';
import frame13 from 'figma:asset/af186e9e9aa190e0b80dd841807826b7ab00a8a6.png';
import frame14 from 'figma:asset/c882cbff30da96722d4f98121e42382bba0eec5b.png';
import frame15 from 'figma:asset/db57dc28cf0d5489f0e248f18a0b5bb3270b5579.png';
import frame16 from 'figma:asset/b53d8d85f3f496ded84ce5fcfe772343c35dcdd5.png';
import frame17 from 'figma:asset/581837d25cb364bec0321ddfe9a1aca5c79501a3.png';
import frame18 from 'figma:asset/e2d43b66df67f1458360d58190d9c8d07a5e46d6.png';
import frame19 from 'figma:asset/54f15349624c3a128da27e38ce5bf6062508a093.png';
import frame20 from 'figma:asset/681d10632bb8c280062d72c9eb0a37436f1eb95a.png';
import frame21 from 'figma:asset/a84f4bb4c1f535dd3c63de64c1ee01dbf67eec44.png';
import frame22 from 'figma:asset/f440cb5f485d22e950f01f75a796109220543faf.png';
import frame23 from 'figma:asset/962586bc1618f2fbd8fc2115703784475bb88b39.png';
import frame24 from 'figma:asset/49fea9e00eb3381a6994baad2c49b9da31a9ef33.png';
import frame25 from 'figma:asset/d71aab0b9fd01620c2c2176d69fd4fdd8858b535.png';
import frame26 from 'figma:asset/a8f640d1df80d3223c6b62c04d90d2b2938e84d1.png';
import frame27 from 'figma:asset/030cb3336a1971e2469c77b0c358fbe9683d23ad.png';
import frame28 from 'figma:asset/fa8539cb07f1db75eef922726fc9bd16e0533534.png';
import frame29 from 'figma:asset/f52200d87be686b173819cdeff5facdad2c73bc7.png';
import frame30 from 'figma:asset/58cce1a97c2e2ff3186d8dc579546268595c71ba.png';

const backgroundFrames = [
  frame1, frame2, frame3, frame4, frame5,
  frame6, frame7, frame8, frame9, frame10,
  frame11, frame12, frame13, frame14, frame15,
  frame16, frame17, frame18, frame19, frame20,
  frame21, frame22, frame23, frame24, frame25,
  frame26, frame27, frame28, frame29, frame30,
];

interface AnalysisStep {
  icon: typeof Clock;
  title: string;
  subtitle: string;
  stage: string;
}

const getStepsForType = (scanType: string): AnalysisStep[] => {
  if (scanType === 'url') {
    return [
      { icon: Cpu,      title: 'URL Feature Extraction',   subtitle: 'Extracting 30 structural parameters',         stage: 'url_extract' },
      { icon: Shield,   title: 'RandomForest Classification', subtitle: 'Running phishing prediction model',        stage: 'url_classify' },
      { icon: Database, title: 'Typosquatting Check',       subtitle: 'Detecting brand impersonation & lookalikes', stage: 'url_lookalike' },
    ];
  }
  if (scanType === 'email') {
    return [
      { icon: Cpu,      title: 'NLP Analysis',              subtitle: 'DistilBERT scanning email content',           stage: 'email_nlp' },
      { icon: Shield,   title: 'Evidence Extraction',       subtitle: 'Flagging urgency, credentials, financial bait', stage: 'email_evidence' },
      { icon: Database, title: 'Embedded URL Scan',         subtitle: 'Scanning links found in email body',          stage: 'email_urls' },
    ];
  }
  if (scanType === 'file') {
    return [
      { icon: Cpu,      title: 'Static Analysis',           subtitle: 'Checking extension, filename & structure',    stage: 'file_static' },
      { icon: Shield,   title: 'Content Extraction',        subtitle: 'Scanning embedded URLs & text patterns',      stage: 'file_content' },
      { icon: Database, title: 'VirusTotal Sandbox',        subtitle: 'Dynamic analysis via VirusTotal',             stage: 'file_vt' },
    ];
  }
  // combined
  return [
    { icon: Clock,    title: 'URL Scan',                  subtitle: 'RandomForest structural analysis',            stage: 'url_scan' },
    { icon: Shield,   title: 'Email Analysis',            subtitle: 'DistilBERT + chain detection',                stage: 'email_scan' },
    { icon: Database, title: 'AI Verdict',                subtitle: 'LLM reasoning & campaign clustering',         stage: 'final' },
  ];
};

export default function Analyzing() {
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);
  const [currentFrame, setCurrentFrame] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const scanType: string = location.state?.scanType || 'url';
  const inputData: InputData = location.state?.inputData || {};
  const apiCalled = useRef(false);

  const analysisSteps = getStepsForType(scanType);

  // ── Background animation ────────────────────────────────────────────────────
  useEffect(() => {
    const testImg = new Image();
    testImg.src = backgroundFrames[backgroundFrames.length - 1];
    const isCached = testImg.complete;

    let frameInterval: ReturnType<typeof setInterval>;
    let burstTimeout: ReturnType<typeof setTimeout> | undefined;

    const stallTimeout = setTimeout(() => {
      if (isCached) {
        frameInterval = setInterval(() => {
          setCurrentFrame((prev) => (prev + 1) % backgroundFrames.length);
        }, 60);
      } else {
        frameInterval = setInterval(() => {
          setCurrentFrame((prev) => (prev + 1) % backgroundFrames.length);
        }, 3);
        burstTimeout = setTimeout(() => {
          clearInterval(frameInterval);
          frameInterval = setInterval(() => {
            setCurrentFrame((prev) => (prev + 1) % backgroundFrames.length);
          }, 60);
        }, 500);
      }
    }, 500);

    return () => {
      clearTimeout(stallTimeout);
      if (burstTimeout) clearTimeout(burstTimeout);
      clearInterval(frameInterval);
    };
  }, []);

  // ── Real API call ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (apiCalled.current) return;
    apiCalled.current = true;

    // Progress animation — advances naturally, slows near 90% until API returns
    let progressTarget = 0;
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        const cap = progressTarget > 0 ? Math.min(progressTarget, 95) : 88;
        if (prev >= cap) return prev;
        return prev + 1;
      });
    }, 80);

    const advanceStep = (stepIdx: number) => {
      setCurrentStep(stepIdx);
      progressTarget = Math.round(((stepIdx + 1) / analysisSteps.length) * 88);
    };

    const finishScan = (result: ScanResult) => {
      clearInterval(progressInterval);
      setProgress(100);
      setTimeout(() => {
        navigate('/result', { state: { scanType, result } });
      }, 600);
    };

    const handleError = (msg: string) => {
      clearInterval(progressInterval);
      setErrorMessage(msg);
      setProgress(100);
      setTimeout(() => {
        navigate('/result', { state: { scanType, result: { error: true, errorMessage: msg, combined_score: 0, verdict: 'UNKNOWN', analysis_provider: 'error' } } });
      }, 2000);
    };

    (async () => {
      try {
        if (scanType === 'url') {
          advanceStep(0);
          await new Promise((r) => setTimeout(r, 400));
          advanceStep(1);
          await new Promise((r) => setTimeout(r, 300));
          advanceStep(2);
          const result = await scanUrl(inputData.url || '');
          finishScan(result);

        } else if (scanType === 'email') {
          advanceStep(0);
          await new Promise((r) => setTimeout(r, 500));
          advanceStep(1);
          await new Promise((r) => setTimeout(r, 300));
          advanceStep(2);
          const result = await scanEmail(inputData.emailText || '');
          finishScan(result);

        } else if (scanType === 'file') {
          advanceStep(0);
          await new Promise((r) => setTimeout(r, 400));
          advanceStep(1);
          const result = await scanFile(inputData.file!);
          advanceStep(2);
          await new Promise((r) => setTimeout(r, 300));
          finishScan(result);

        } else {
          // combined — SSE streaming: real stage events drive step advancement
          const result = await scanCombined(
            inputData.combinedUrl || '',
            inputData.combinedEmail || '',
            (stage) => {
              if (stage === 'url_scan')   advanceStep(0);
              if (stage === 'email_scan') advanceStep(1);
              if (stage === 'final')      advanceStep(2);
            }
          );
          finishScan(result);
        }
      } catch (err) {
        handleError((err as Error).message || 'Unexpected error during scan');
      }
    })();

    return () => {
      clearInterval(progressInterval);
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen bg-black relative py-12 px-4">
      {/* Base Background */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage: `url(${frame1})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
          opacity: 0.5,
        }}
      />

      {/* Animated Background Layer */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage: `url(${backgroundFrames[currentFrame]})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
          opacity: 0.5,
        }}
      />

      {/* Content */}
      <div className="relative z-10 max-w-4xl mx-auto">
        {/* Title */}
        <div className="text-center mb-12">
          <h1 className="text-3xl font-bold text-white mb-2">Analyzing Threat…</h1>
          <p className="text-gray-400">
            {errorMessage
              ? 'An error occurred — redirecting to results…'
              : 'Please wait while we scan for potential risks'}
          </p>
        </div>

        {/* Analysis Steps */}
        <div className="space-y-4 mb-12">
          {analysisSteps.map((step, index) => {
            const Icon = step.icon;
            const isActive = currentStep === index;
            const isCompleted = currentStep > index;

            return (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.2 }}
              >
                <GlassCard
                  className={`p-6 transition-all duration-300 ${
                    isActive ? 'ring-2 ring-blue-500 shadow-xl' : ''
                  }`}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`p-3 rounded-xl transition-all duration-300 ${
                        errorMessage && isActive
                          ? 'bg-red-500/20'
                          : isCompleted
                          ? 'bg-green-500/20'
                          : isActive
                          ? 'bg-blue-500/20'
                          : 'bg-gray-700/50'
                      }`}
                    >
                      {errorMessage && isActive ? (
                        <AlertCircle size={24} className="text-red-400" />
                      ) : isCompleted ? (
                        <CheckCircle2 size={24} className="text-green-400" />
                      ) : (
                        <Icon
                          size={24}
                          className={isActive ? 'text-blue-400' : 'text-gray-500'}
                        />
                      )}
                    </div>
                    <div className="flex-1">
                      <h3
                        className={`font-semibold ${
                          isActive || isCompleted ? 'text-white' : 'text-gray-500'
                        }`}
                      >
                        {step.title}
                      </h3>
                      <p className="text-sm text-gray-400">{step.subtitle}</p>
                    </div>
                    {isActive && !errorMessage && (
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                        className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full"
                      />
                    )}
                  </div>
                </GlassCard>
              </motion.div>
            );
          })}
        </div>

        {/* Progress Bar */}
        <GlassCard className="p-6">
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-sm font-medium text-gray-300">Analysis Progress</span>
              <span className="text-lg font-bold text-blue-400">{progress}%</span>
            </div>
            <div className="h-3 bg-gray-700/50 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-blue-500 to-blue-600"
                initial={{ width: 0 }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
          </div>
        </GlassCard>
      </div>
    </div>
  );
}