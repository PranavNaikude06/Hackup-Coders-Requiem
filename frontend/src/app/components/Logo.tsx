import { Shield } from 'lucide-react';

interface LogoProps {
  size?: 'small' | 'large';
}

export function Logo({ size = 'large' }: LogoProps) {
  const iconSize = size === 'large' ? 48 : 32;
  const titleSize = size === 'large' ? 'text-4xl' : 'text-2xl';
  const subtitleSize = size === 'large' ? 'text-base' : 'text-sm';
  
  return (
    <div className="flex flex-col items-center gap-3">
      <div className="text-center">
        <h1 className={`${titleSize} font-bold text-white`}>ThreatLens</h1>
        {size === 'large' && (
          <p className={`${subtitleSize} text-gray-400 mt-1`}>
            Analyze suspicious links and detect phishing instantly
          </p>
        )}
      </div>
    </div>
  );
}