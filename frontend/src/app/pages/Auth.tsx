import { useState } from 'react';
import { useNavigate } from 'react-router';
import { Mail, Lock, User, ChevronLeft, Shield } from 'lucide-react';
import { GlassCard } from '../components/GlassCard';
import { EmissionButton } from '../components/EmissionButton';
import { Logo } from '../components/Logo';
import bgImage from 'figma:asset/62bbae5fd46eea7de9c86b6eeed87297c1e7a626.png';

export default function Auth() {
  const navigate = useNavigate();
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // TODO: Implement actual authentication later
    navigate('/');
  };

  return (
    <div className="min-h-screen bg-black relative flex items-center justify-center p-4">
      {/* Background Image matching Landing */}
      <div 
        className="fixed inset-0 opacity-40 mix-blend-screen"
        style={{
          backgroundImage: `url(${bgImage})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
        }}
      />

      {/* Cyber Grid Overlay */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(0,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,255,0.02)_1px,transparent_1px)] bg-[size:30px_30px] pointer-events-none" />

      {/* Back Button */}
      <button 
        onClick={() => navigate('/')}
        className="absolute top-6 left-6 z-20 flex items-center gap-2 text-gray-400 hover:text-cyan-400 transition-colors"
      >
        <ChevronLeft size={20} />
        <span>Back to Home</span>
      </button>

      <div className="relative z-10 w-full max-w-md">
        <div className="flex justify-center mb-8">
          <Logo size="large" />
        </div>

        <GlassCard className="p-8 border-gray-800">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400 font-syncopate">
              {isLogin ? 'SYSTEM LOGIN' : 'INITIALIZE ACCESS'}
            </h2>
            <p className="text-gray-400 text-sm mt-2">
              {isLogin ? 'Authenticate to access the ThreatLens network.' : 'Create an operative ID for ThreatLens.'}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-4">
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail size={18} className="text-gray-500" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Operative Email"
                  className="w-full bg-black/50 border border-gray-700/50 rounded-lg pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-mono text-sm"
                  required
                />
              </div>

              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock size={18} className="text-gray-500" />
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Decryption Key (Password)"
                  className="w-full bg-black/50 border border-gray-700/50 rounded-lg pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-mono text-sm"
                  required
                />
              </div>
            </div>

            <EmissionButton
              onClick={() => {}}
              disabled={!email || !password}
              icon={isLogin ? <Shield size={18} /> : <User size={18} />}
            >
              {isLogin ? 'AUTHENTICATE' : 'ESTABLISH LINK'}
            </EmissionButton>

            <div className="text-center mt-6">
              <button
                type="button"
                onClick={() => setIsLogin(!isLogin)}
                className="text-gray-400 hover:text-cyan-400 text-sm transition-colors cursor-pointer"
              >
                {isLogin 
                  ? "Don't have clearance? Request access." 
                  : "Already an operative? Access system."}
              </button>
            </div>
          </form>
        </GlassCard>
      </div>
    </div>
  );
}
