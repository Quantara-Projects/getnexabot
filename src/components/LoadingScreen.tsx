import React from 'react';

type Props = {
  onVerify: () => void;
  // optional slot to place user-selected content in the center
  selectedContent?: React.ReactNode;
  title?: string;
  subtitle?: string;
};

const LoadingScreen: React.FC<Props> = ({ onVerify, selectedContent, title = 'Welcome to NexaBot', subtitle = "Tap to continue" }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-gradient-to-b from-white/96 to-white/90 backdrop-blur-sm">
      <div className="w-full max-w-xl mx-4 p-8 bg-white rounded-3xl shadow-2xl text-center">
        <h2 className="mt-1 text-2xl sm:text-3xl font-extrabold tracking-tight">{title}</h2>
        <p className="mt-2 text-sm text-muted-foreground max-w-xl mx-auto">{subtitle}</p>

        <div className="mt-8 flex items-center justify-center">
          <button
            onClick={onVerify}
            className="relative group w-44 h-44 sm:w-56 sm:h-56 rounded-2xl bg-gradient-to-br from-primary to-violet-600 shadow-xl flex items-center justify-center overflow-hidden focus:outline-none"
            aria-label="Proceed"
          >
            {/* Animated layered shapes */}
            <div className="absolute w-full h-full flex items-center justify-center">
              <div className="animate-ring mr-[-4rem]">
                <div className="w-28 h-28 sm:w-36 sm:h-36 rounded-xl bg-white/10 backdrop-blur-sm" />
              </div>
              <div className="animate-ring-delay">
                <div className="w-20 h-20 sm:w-28 sm:h-28 rounded-xl bg-white/8 border border-white/10" />
              </div>
            </div>

            {/* selected content slot */}
            <div className="relative z-10 flex items-center justify-center text-white text-sm sm:text-base font-semibold">
              {selectedContent ? selectedContent : <span className="px-3 py-2 rounded-md bg-white/10">{subtitle}</span>}
            </div>

            <span className="absolute bottom-3 text-xs text-white/80 opacity-90">{subtitle}</span>
          </button>
        </div>

        <div className="mt-6">
          <div className="text-xs text-muted-foreground">This quick interaction helps prevent automated bots from abusing the service.</div>
        </div>
      </div>

      <style>{`
        @keyframes ring-rotate { 0% { transform: rotate(0deg) translateX(0); } 50% { transform: rotate(12deg) translateX(4px); } 100% { transform: rotate(0deg) translateX(0); } }
        @keyframes ring-morph { 0% { border-radius: 22px; } 50% { border-radius: 12px; } 100% { border-radius: 22px; } }
        .animate-ring > div { animation: ring-morph 3.2s ease-in-out infinite; box-shadow: 0 10px 30px rgba(99,102,241,0.12); }
        .animate-ring { animation: ring-rotate 5s linear infinite; }
        .animate-ring-delay { animation: ring-rotate 7s linear infinite reverse; opacity: 0.9; }

        /* subtle float on hover */
        .group:hover .animate-ring > div, .group:hover .animate-ring-delay > div { transform: translateY(-6px); transition: transform .45s cubic-bezier(.2,.9,.4,1); }
      `}</style>
    </div>
  );
};

export default LoadingScreen;
