import { useState } from 'react';
import { Logo } from '../components/Logo';
import { InputSection } from '../components/InputSection';
import type { InputData } from '../components/InputSection';
import { HowItWorks } from '../components/HowItWorks';
import { EmissionButton } from '../components/EmissionButton';
import { Scan, User } from 'lucide-react';
import { useNavigate } from 'react-router';
import bgImage from 'figma:asset/62bbae5fd46eea7de9c86b6eeed87297c1e7a626.png';

type ScanType = 'url' | 'file' | 'email' | 'combined' | null;

export default function Landing() {
  const navigate = useNavigate();
  const [scanType, setScanType] = useState<ScanType>(null);
  const [hasData, setHasData] = useState(false);
  const [inputData, setInputData] = useState<InputData>({});

  const handleScanTypeChange = (type: ScanType, dataAvailable: boolean, data?: InputData) => {
    setScanType(type);
    setHasData(dataAvailable);
    if (data) setInputData(data);
  };

  const handleStartScan = () => {
    if (scanType && hasData) {
      navigate('/analyzing', { state: { scanType, inputData } });
    }
  };

  const isScanEnabled = scanType !== null && hasData;

  return (
    <div className="min-h-screen bg-black relative py-12 px-4">
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
        {/* Top Right Auth Button */}
        <div className="absolute top-6 right-6 z-20">
          <button 
            onClick={() => navigate('/auth')}
            className="flex items-center gap-2 px-4 py-2 bg-black/40 border border-gray-800 hover:border-cyan-500 rounded-lg text-sm text-gray-300 hover:text-cyan-400 transition-all shadow-[0_0_15px_-5px_rgba(0,255,255,0.2)] backdrop-blur-md"
          >
            <User size={16} />
            <span className="font-mono">SIGN IN</span>
          </button>
        </div>

        {/* Header - Only show logo when no scan type selected */}
        {scanType === null && (
          <div className="mb-12">
            <Logo size="large" />
          </div>
        )}

        {/* Main Input Card */}
        <div className="flex justify-center mb-8">
          <InputSection onScanTypeChange={handleScanTypeChange} />
        </div>

        {/* CTA Button */}
        {scanType !== null && (
          <div className="flex justify-center mb-16">
            <EmissionButton
              onClick={handleStartScan}
              disabled={!isScanEnabled}
              icon={<Scan size={24} />}
            >
              Start Threat Scan
            </EmissionButton>
          </div>
        )}

        {/* How It Works - Only shown before selecting a scan type */}
        {scanType === null && (
          <div className="flex justify-center">
            <HowItWorks />
          </div>
        )}
      </div>
    </div>
  );
}