import { useState } from 'react';
import { Logo } from '../components/Logo';
import { InputSection } from '../components/InputSection';
import type { InputData } from '../components/InputSection';
import { HowItWorks } from '../components/HowItWorks';
import { EmissionButton } from '../components/EmissionButton';
import { Scan } from 'lucide-react';
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