import { FileText, Brain, FileCheck, ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';

const steps = [
  {
    icon: FileText,
    title: 'Input Data',
    description: 'URL/File/Email',
  },
  {
    icon: Brain,
    title: 'AI Threat Analysis',
    description: 'Real-time scanning',
  },
  {
    icon: FileCheck,
    title: 'Risk Report Generated',
    description: 'Detailed results',
  },
];

export function HowItWorks() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="max-w-4xl w-full">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-center gap-2 text-white hover:text-blue-400 transition-colors mb-4"
      >
        <h2 className="text-2xl font-semibold">How It Works</h2>
        <motion.div
          animate={{ rotate: isOpen ? 180 : 0 }}
          transition={{ duration: 0.3 }}
        >
          <ChevronDown size={24} />
        </motion.div>
      </button>
      
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pt-4">
              {steps.map((step, index) => {
                const Icon = step.icon;
                return (
                  <div key={index} className="flex flex-col items-center text-center">
                    <div className="bg-blue-500/20 p-4 rounded-2xl mb-4">
                      <Icon size={32} className="text-blue-400" />
                    </div>
                    <h3 className="font-semibold text-white mb-1">{step.title}</h3>
                    <p className="text-sm text-gray-400">{step.description}</p>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
