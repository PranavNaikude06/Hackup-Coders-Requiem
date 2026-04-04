import { useState, useRef } from 'react';
import { Link as LinkIcon, Upload, Mail, Layers } from 'lucide-react';
import { GlassCard } from './GlassCard';
import { motion, AnimatePresence } from 'motion/react';

type ScanType = 'url' | 'file' | 'email' | 'combined' | null;

export interface InputData {
  url?: string;
  emailText?: string;
  file?: File;
  combinedUrl?: string;
  combinedEmail?: string;
}

interface InputSectionProps {
  onScanTypeChange: (type: ScanType, hasData: boolean, inputData?: InputData) => void;
  selectedScanType: ScanType;
}

export function InputSection({ onScanTypeChange, selectedScanType }: InputSectionProps) {
  const [url, setUrl] = useState('');
  const [email, setEmail] = useState('');
  const [fileName, setFileName] = useState('');
  const [combinedUrl, setCombinedUrl] = useState('');
  const [combinedEmail, setCombinedEmail] = useState('');
  const fileRef = useRef<File | undefined>(undefined);

  const handleTypeSelect = (type: ScanType) => {
    // Reset other fields when switching types
    setUrl('');
    setEmail('');
    setFileName('');
    setCombinedUrl('');
    setCombinedEmail('');
    fileRef.current = undefined;
    onScanTypeChange(type, false);
  };

  const handleUrlChange = (value: string) => {
    setUrl(value);
    onScanTypeChange('url', value.trim().length > 0, { url: value });
  };

  const handleEmailChange = (value: string) => {
    setEmail(value);
    onScanTypeChange('email', value.trim().length > 0, { emailText: value });
  };

  const handleCombinedChange = (urlValue: string, emailValue: string) => {
    setCombinedUrl(urlValue);
    setCombinedEmail(emailValue);
    const hasData = urlValue.trim().length > 0 && emailValue.trim().length > 0;
    onScanTypeChange('combined', hasData, { combinedUrl: urlValue, combinedEmail: emailValue });
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      fileRef.current = e.target.files[0];
      setFileName(e.target.files[0].name);
      onScanTypeChange('file', true, { file: e.target.files[0] });
    }
  };

  return (
    <GlassCard className="p-8 max-w-3xl w-full">
      <div className="space-y-6">
        {/* Selection Buttons - Only show when nothing is selected */}
        {selectedScanType === null && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-4"
          >
            <h2 className="text-xl font-semibold text-white text-center mb-6">
              Choose Analysis Type
            </h2>
            
            <motion.button
              onClick={() => handleTypeSelect('url')}
              className="w-full flex items-center gap-4 p-6 bg-black/40 border-2 border-blue-500/30 rounded-xl hover:border-blue-500 hover:bg-blue-500/10 transition-all duration-75 group"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.98 }}
              transition={{ type: 'spring', stiffness: 800, damping: 15 }}
            >
              <div className="bg-blue-500/20 p-3 rounded-xl group-hover:bg-blue-500/30 transition-colors">
                <LinkIcon size={24} className="text-blue-400" />
              </div>
              <div className="text-left flex-1">
                <h3 className="font-semibold text-white text-lg">URL Scanner</h3>
                <p className="text-sm text-gray-400">Analyze suspicious links and websites</p>
              </div>
            </motion.button>

            <motion.button
              onClick={() => handleTypeSelect('file')}
              className="w-full flex items-center gap-4 p-6 bg-black/40 border-2 border-blue-500/30 rounded-xl hover:border-blue-500 hover:bg-blue-500/10 transition-all duration-75 group"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.98 }}
              transition={{ type: 'spring', stiffness: 800, damping: 15 }}
            >
              <div className="bg-blue-500/20 p-3 rounded-xl group-hover:bg-blue-500/30 transition-colors">
                <Upload size={24} className="text-blue-400" />
              </div>
              <div className="text-left flex-1">
                <h3 className="font-semibold text-white text-lg">File Upload</h3>
                <p className="text-sm text-gray-400">Upload suspicious files for scanning</p>
              </div>
            </motion.button>

            <motion.button
              onClick={() => handleTypeSelect('email')}
              className="w-full flex items-center gap-4 p-6 bg-black/40 border-2 border-blue-500/30 rounded-xl hover:border-blue-500 hover:bg-blue-500/10 transition-all duration-75 group"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.98 }}
              transition={{ type: 'spring', stiffness: 800, damping: 15 }}
            >
              <div className="bg-blue-500/20 p-3 rounded-xl group-hover:bg-blue-500/30 transition-colors">
                <Mail size={24} className="text-blue-400" />
              </div>
              <div className="text-left flex-1">
                <h3 className="font-semibold text-white text-lg">Email Analyzer</h3>
                <p className="text-sm text-gray-400">Paste and analyze email content</p>
              </div>
            </motion.button>

            <motion.button
              onClick={() => handleTypeSelect('combined')}
              className="w-full flex items-center gap-4 p-6 bg-black/40 border-2 border-blue-500/30 rounded-xl hover:border-blue-500 hover:bg-blue-500/10 transition-all duration-75 group"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.98 }}
              transition={{ type: 'spring', stiffness: 800, damping: 15 }}
            >
              <div className="bg-blue-500/20 p-3 rounded-xl group-hover:bg-blue-500/30 transition-colors">
                <Layers size={24} className="text-blue-400" />
              </div>
              <div className="text-left flex-1">
                <h3 className="font-semibold text-white text-lg">Combined Analysis</h3>
                <p className="text-sm text-gray-400">Analyze both URL and email together</p>
              </div>
            </motion.button>
          </motion.div>
        )}

        {/* URL Scanner Input */}
        <AnimatePresence>
          {selectedScanType === 'url' && (
            <motion.div className="space-y-4">
              {/* Selected Type Header - Pop up animation */}
              <motion.div
                initial={{ opacity: 0, scale: 0.8, y: -20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                transition={{ type: 'spring', duration: 0.3 }}
                className="flex items-center justify-between bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border-2 border-blue-500 rounded-xl p-4 shadow-lg shadow-blue-500/20"
              >
                <div className="flex items-center gap-3">
                  <div className="bg-blue-500/30 p-2 rounded-lg">
                    <LinkIcon size={24} className="text-blue-400" />
                  </div>
                  <h3 className="font-semibold text-white text-lg">URL Scanner</h3>
                </div>
                <button
                  onClick={() => handleTypeSelect(null)}
                  className="text-sm text-gray-300 hover:text-white transition-colors"
                >
                  Change
                </button>
              </motion.div>

              {/* Input Field - Slide down */}
              <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1, duration: 0.3 }}
              >
                <input
                  type="text"
                  placeholder="Enter URL to scan… (e.g., https://example.com)"
                  value={url}
                  onChange={(e) => handleUrlChange(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl border border-blue-500/30 bg-black/40 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  autoFocus
                />
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* File Upload Input */}
        <AnimatePresence>
          {selectedScanType === 'file' && (
            <motion.div className="space-y-4">
              {/* Selected Type Header - Pop up animation */}
              <motion.div
                initial={{ opacity: 0, scale: 0.8, y: -20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                transition={{ type: 'spring', duration: 0.3 }}
                className="flex items-center justify-between bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border-2 border-blue-500 rounded-xl p-4 shadow-lg shadow-blue-500/20"
              >
                <div className="flex items-center gap-3">
                  <div className="bg-blue-500/30 p-2 rounded-lg">
                    <Upload size={24} className="text-blue-400" />
                  </div>
                  <h3 className="font-semibold text-white text-lg">File Upload</h3>
                </div>
                <button
                  onClick={() => handleTypeSelect(null)}
                  className="text-sm text-gray-300 hover:text-white transition-colors"
                >
                  Change
                </button>
              </motion.div>

              {/* Input Field - Slide down */}
              <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1, duration: 0.3 }}
              >
                <label className="block">
                  <input
                    type="file"
                    onChange={handleFileChange}
                    className="hidden"
                    accept=".pdf,.docx,.txt"
                  />
                  <div className="border-2 border-dashed border-gray-600 rounded-xl p-8 text-center cursor-pointer hover:border-blue-400 hover:bg-blue-500/10 transition-all duration-200">
                    <Upload size={32} className="mx-auto text-gray-400 mb-2" />
                    <p className="text-white font-medium mb-1">
                      {fileName || 'Click to upload suspicious file'}
                    </p>
                    <p className="text-sm text-gray-400">Supports PDF, DOCX, TXT</p>
                  </div>
                </label>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Email Analyzer Input */}
        <AnimatePresence>
          {selectedScanType === 'email' && (
            <motion.div className="space-y-4">
              {/* Selected Type Header - Pop up animation */}
              <motion.div
                initial={{ opacity: 0, scale: 0.8, y: -20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                transition={{ type: 'spring', duration: 0.3 }}
                className="flex items-center justify-between bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border-2 border-blue-500 rounded-xl p-4 shadow-lg shadow-blue-500/20"
              >
                <div className="flex items-center gap-3">
                  <div className="bg-blue-500/30 p-2 rounded-lg">
                    <Mail size={24} className="text-blue-400" />
                  </div>
                  <h3 className="font-semibold text-white text-lg">Email Analyzer</h3>
                </div>
                <button
                  onClick={() => handleTypeSelect(null)}
                  className="text-sm text-gray-300 hover:text-white transition-colors"
                >
                  Change
                </button>
              </motion.div>

              {/* Input Field - Slide down */}
              <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1, duration: 0.3 }}
              >
                <textarea
                  placeholder="Paste email content here…"
                  value={email}
                  onChange={(e) => handleEmailChange(e.target.value)}
                  rows={6}
                  className="w-full px-4 py-3 rounded-xl border border-blue-500/30 bg-black/40 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all resize-none"
                  autoFocus
                />
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Combined Analysis Input */}
        <AnimatePresence>
          {selectedScanType === 'combined' && (
            <motion.div className="space-y-4">
              {/* Selected Type Header - Pop up animation */}
              <motion.div
                initial={{ opacity: 0, scale: 0.8, y: -20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                transition={{ type: 'spring', duration: 0.3 }}
                className="flex items-center justify-between bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border-2 border-blue-500 rounded-xl p-4 shadow-lg shadow-blue-500/20"
              >
                <div className="flex items-center gap-3">
                  <div className="bg-blue-500/30 p-2 rounded-lg">
                    <Layers size={24} className="text-blue-400" />
                  </div>
                  <h3 className="font-semibold text-white text-lg">Combined Analysis</h3>
                </div>
                <button
                  onClick={() => handleTypeSelect(null)}
                  className="text-sm text-gray-300 hover:text-white transition-colors"
                >
                  Change
                </button>
              </motion.div>

              {/* Input Fields - Slide down */}
              <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1, duration: 0.3 }}
                className="space-y-4"
              >
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Suspicious URL
                  </label>
                  <input
                    type="text"
                    placeholder="Enter URL to scan… (e.g., https://example.com)"
                    value={combinedUrl}
                    onChange={(e) => handleCombinedChange(e.target.value, combinedEmail)}
                    className="w-full px-4 py-3 rounded-xl border border-blue-500/30 bg-black/40 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    autoFocus
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Email Content
                  </label>
                  <textarea
                    placeholder="Paste email content here…"
                    value={combinedEmail}
                    onChange={(e) => handleCombinedChange(combinedUrl, e.target.value)}
                    rows={6}
                    className="w-full px-4 py-3 rounded-xl border border-blue-500/30 bg-black/40 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all resize-none"
                  />
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </GlassCard>
  );
}