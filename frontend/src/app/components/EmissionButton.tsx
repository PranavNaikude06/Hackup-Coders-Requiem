import { motion } from 'motion/react';
import { ReactNode, useState, useMemo } from 'react';

interface EmissionButtonProps {
  onClick: () => void;
  disabled: boolean;
  children: ReactNode;
  icon?: ReactNode;
}

export function EmissionButton({ onClick, disabled, children, icon }: EmissionButtonProps) {
  const [isHovered, setIsHovered] = useState(false);

  // Line configuration for full coverage
  const minLineLength = 8;
  const maxLineLength = 20;
  
  // Number of lines to fully span button dimensions
  const topBottomLineCount = 20; // More lines to span full button width
  const leftRightLineCount = 9; // More lines to span full button height
  
  // Button dimensions
  const horizontalWidth = 206; // Extended by 15 more pixels on each side (176 + 30)
  const horizontalHalfWidth = horizontalWidth / 2; // 103px

  // Generate random line lengths once using useMemo
  const topLineLengths = useMemo(
    () => Array.from({ length: topBottomLineCount }, () => 
      minLineLength + Math.random() * (maxLineLength - minLineLength)
    ),
    []
  );

  const bottomLineLengths = useMemo(
    () => Array.from({ length: topBottomLineCount }, () => 
      minLineLength + Math.random() * (maxLineLength - minLineLength)
    ),
    []
  );

  const leftLineLengths = useMemo(
    () => Array.from({ length: leftRightLineCount }, () => 
      minLineLength + Math.random() * (maxLineLength - minLineLength)
    ),
    []
  );

  const rightLineLengths = useMemo(
    () => Array.from({ length: leftRightLineCount }, () => 
      minLineLength + Math.random() * (maxLineLength - minLineLength)
    ),
    []
  );

  return (
    <div className="relative inline-flex items-center justify-center p-[50px]">
      {/* Clipping container for overflow control */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {/* Top edge - vertical lines extending UPWARD from left edge to right edge */}
        {Array.from({ length: topBottomLineCount }, (_, i) => {
          const leftPosition = -horizontalHalfWidth + (i / (topBottomLineCount - 1)) * horizontalWidth;
          return (
            <motion.div
              key={`top-${i}`}
              className="absolute bg-blue-500"
              style={{
                width: '1.5px',
                left: `calc(50% + ${leftPosition}px)`,
                bottom: 'calc(50% + 32px)', // Button top edge
                transformOrigin: 'bottom',
              }}
              animate={isHovered && !disabled ? { height: `${topLineLengths[i]}px` } : { height: '0px' }}
              transition={{ duration: 0.2, ease: 'easeOut' }}
            />
          );
        })}

        {/* Bottom edge - vertical lines extending DOWNWARD from left edge to right edge */}
        {Array.from({ length: topBottomLineCount }, (_, i) => {
          const leftPosition = -horizontalHalfWidth + (i / (topBottomLineCount - 1)) * horizontalWidth;
          return (
            <motion.div
              key={`bottom-${i}`}
              className="absolute bg-blue-500"
              style={{
                width: '1.5px',
                left: `calc(50% + ${leftPosition}px)`,
                top: 'calc(50% + 32px)', // Button bottom edge
                transformOrigin: 'top',
              }}
              animate={isHovered && !disabled ? { height: `${bottomLineLengths[i]}px` } : { height: '0px' }}
              transition={{ duration: 0.2, ease: 'easeOut' }}
            />
          );
        })}

        {/* Left edge - horizontal lines extending LEFTWARD from top edge to bottom edge */}
        {Array.from({ length: leftRightLineCount }, (_, i) => {
          const buttonHeight = 64; // Approximate button height
          const topPosition = -buttonHeight / 2 + (i / (leftRightLineCount - 1)) * buttonHeight;
          return (
            <motion.div
              key={`left-${i}`}
              className="absolute bg-blue-500"
              style={{
                height: '1.5px',
                top: `calc(50% + ${topPosition}px)`,
                right: `calc(50% + ${horizontalHalfWidth}px)`, // Start from horizontal line edge
                transformOrigin: 'right',
              }}
              animate={isHovered && !disabled ? { width: `${leftLineLengths[i]}px` } : { width: '0px' }}
              transition={{ duration: 0.2, ease: 'easeOut' }}
            />
          );
        })}

        {/* Right edge - horizontal lines extending RIGHTWARD from top edge to bottom edge */}
        {Array.from({ length: leftRightLineCount }, (_, i) => {
          const buttonHeight = 64;
          const topPosition = -buttonHeight / 2 + (i / (leftRightLineCount - 1)) * buttonHeight;
          return (
            <motion.div
              key={`right-${i}`}
              className="absolute bg-blue-500"
              style={{
                height: '1.5px',
                top: `calc(50% + ${topPosition}px)`,
                left: `calc(50% + ${horizontalHalfWidth}px)`, // Start from horizontal line edge
                transformOrigin: 'left',
              }}
              animate={isHovered && !disabled ? { width: `${rightLineLengths[i]}px` } : { width: '0px' }}
              transition={{ duration: 0.2, ease: 'easeOut' }}
            />
          );
        })}

        {/* Corner accent lines - top left */}
        <motion.div
          className="absolute bg-blue-500"
          style={{
            height: '1.5px',
            top: 'calc(50% - 32px)',
            right: `calc(50% + ${horizontalHalfWidth}px)`,
            transformOrigin: 'right',
          }}
          animate={isHovered && !disabled ? { width: '12px' } : { width: '0px' }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        />

        {/* Corner accent lines - top right */}
        <motion.div
          className="absolute bg-blue-500"
          style={{
            height: '1.5px',
            top: 'calc(50% - 32px)',
            left: `calc(50% + ${horizontalHalfWidth}px)`,
            transformOrigin: 'left',
          }}
          animate={isHovered && !disabled ? { width: '12px' } : { width: '0px' }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        />

        {/* Corner accent lines - bottom left */}
        <motion.div
          className="absolute bg-blue-500"
          style={{
            height: '1.5px',
            top: 'calc(50% + 32px)',
            right: `calc(50% + ${horizontalHalfWidth}px)`,
            transformOrigin: 'right',
          }}
          animate={isHovered && !disabled ? { width: '12px' } : { width: '0px' }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        />

        {/* Corner accent lines - bottom right */}
        <motion.div
          className="absolute bg-blue-500"
          style={{
            height: '1.5px',
            top: 'calc(50% + 32px)',
            left: `calc(50% + ${horizontalHalfWidth}px)`,
            transformOrigin: 'left',
          }}
          animate={isHovered && !disabled ? { width: '12px' } : { width: '0px' }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        />
      </div>

      {/* Button */}
      <motion.button
        onClick={onClick}
        disabled={disabled}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        className={`relative z-10 group flex items-center gap-3 rounded-xl transition-all duration-200 shadow-lg font-semibold ${ !disabled ? 'bg-gradient-to-r from-blue-500 to-blue-600 text-white hover:shadow-xl cursor-pointer' : 'bg-gray-300 text-gray-500 cursor-not-allowed' } px-[20px] py-[16px] text-[18px]`}
        whileHover={disabled ? {} : { 
          scale: 1.02,
          boxShadow: '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)',
        }}
        transition={{ duration: 0.2, ease: 'easeOut' }}
      >
        {icon && (
          <motion.div
            animate={isHovered && !disabled ? { rotate: 12 } : { rotate: 0 }}
            transition={{ duration: 0.2 }}
          >
            {icon}
          </motion.div>
        )}
        {children}
      </motion.button>
    </div>
  );
}