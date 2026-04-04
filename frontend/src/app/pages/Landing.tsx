import { useState } from 'react';
import { Logo } from '../components/Logo';
import { InputSection } from '../components/InputSection';
import type { InputData } from '../components/InputSection';
import { HowItWorks } from '../components/HowItWorks';
import { EmissionButton } from '../components/EmissionButton';
import { Scan, User, LogOut, ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router';
import bgImage from 'figma:asset/62bbae5fd46eea7de9c86b6eeed87297c1e7a626.png';
import { useAuth } from '../contexts/AuthContext';
import { signOut } from 'firebase/auth';
import { auth } from '../firebase';

type ScanType = 'url' | 'file' | 'email' | 'combined' | null;

export default function Landing() {
  const navigate = useNavigate();
  const { currentUser } = useAuth();
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
        {scanType === null && (
          <div className="absolute top-6 right-6 z-20">
            {currentUser ? (
              <div className="flex items-center gap-4 bg-black/40 border border-gray-800 rounded-lg pr-2 py-1 pl-4 backdrop-blur-md">
                <span className="text-gray-300 font-mono text-sm whitespace-nowrap">
                  Welcome, <span className="text-cyan-400">{currentUser.displayName || currentUser.email?.split('@')[0]}</span>
                </span>
                <button 
                  onClick={() => signOut(auth)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-black/40 border border-gray-700 hover:border-red-500 rounded-md text-sm text-gray-400 hover:text-red-400 transition-all shadow-[0_0_15px_-5px_rgba(255,0,0,0.2)]"
                  title="Sign Out"
                >
                  <LogOut size={16} />
                </button>
              </div>
            ) : (
              <button 
                onClick={() => navigate('/auth')}
                className="flex items-center gap-2 px-4 py-2 bg-black/40 border border-gray-800 hover:border-cyan-500 rounded-lg text-sm text-gray-300 hover:text-cyan-400 transition-all shadow-[0_0_15px_-5px_rgba(0,255,255,0.2)] backdrop-blur-md"
              >
                <User size={16} />
                <span className="font-mono">SIGN IN</span>
              </button>
            )}
          </div>
        )}

        {/* Header/Back Button */}
        <div className="mb-12 flex justify-between items-center">
          {scanType === null ? (
            <div className="w-full">
              <Logo size="large" />
            </div>
          ) : (
            <button
              onClick={() => handleScanTypeChange(null, false)}
              className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors group"
            >
              <div className="p-2 rounded-lg bg-gray-800/50 group-hover:bg-gray-700/50 transition-colors border border-gray-700">
                <ArrowLeft size={20} />
              </div>
              <span className="font-semibold">Back to Home</span>
            </button>
          )}
        </div>

        {/* Main Input Card */}
        <div className="flex justify-center mb-8">
          <InputSection selectedScanType={scanType} onScanTypeChange={handleScanTypeChange} />
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