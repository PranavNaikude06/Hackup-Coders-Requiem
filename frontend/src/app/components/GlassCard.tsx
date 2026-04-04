import { ReactNode, CSSProperties } from 'react';

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}

export function GlassCard({ children, className = '', style }: GlassCardProps) {
  return (
    <div 
      className={`bg-black/40 backdrop-blur-md rounded-2xl shadow-xl border border-blue-500/20 ${className}`}
      style={style}
    >
      {children}
    </div>
  );
}