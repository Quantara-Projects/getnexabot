import React from 'react';

type Props = { onVerify: () => void };

const LoadingScreen: React.FC<Props> = ({ onVerify }) => {
  const robotImg = 'https://cdn.builder.io/api/v1/image/assets%2Ff7636dbc154444f9897eafaf4c70d8a5%2F7dad355231794df38f24a54cb7869668?format=webp&width=800';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-gradient-to-b from-white/95 to-white/90 backdrop-blur-sm">
      <div className="w-full max-w-lg mx-4 p-8 bg-white rounded-2xl shadow-xl text-center">
        <img src={robotImg} alt="robot" className="mx-auto w-28 h-28 object-contain -mt-12" />
        <h2 className="mt-2 text-2xl font-bold">Welcome to NexaBot</h2>
        <p className="mt-2 text-sm text-muted-foreground">Tap the robot to confirm you're human and continue</p>

        <div className="mt-6 flex items-center justify-center">
          <button
            onClick={onVerify}
            className="relative group w-40 h-40 rounded-full bg-gradient-to-br from-primary to-violet-600 shadow-lg flex items-center justify-center overflow-hidden focus:outline-none"
            aria-label="Verify human"
          >
            <span className="absolute inset-0 bg-gradient-to-r from-white/10 to-white/5 opacity-40 transform -translate-x-6 -rotate-12 group-hover:translate-x-0 transition-all duration-700"></span>
            <svg className="w-24 h-24 transform group-active:scale-95 transition-transform duration-300" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="g1" x1="0" x2="1">
                  <stop offset="0%" stopColor="#fff" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#fff" stopOpacity="0.3" />
                </linearGradient>
              </defs>
              <g>
                <circle cx="50" cy="35" r="18" fill="url(#g1)" />
                <rect x="30" y="55" width="40" height="22" rx="6" fill="#fff" opacity="0.15" />
                <circle cx="42" cy="33" r="3" fill="#111827" />
                <circle cx="58" cy="33" r="3" fill="#111827" />
                <rect x="44" y="42" width="12" height="4" rx="2" fill="#111827" />
              </g>
            </svg>

            <span className="absolute -bottom-6 text-xs text-white opacity-0 group-hover:opacity-100 transition-opacity duration-300">Click to continue</span>
          </button>
        </div>

        <div className="mt-6">
          <div className="text-xs text-muted-foreground">This quick interaction helps prevent automated bots from abusing the service.</div>
        </div>
      </div>

      <style>{`
        @keyframes floaty { 0% { transform: translateY(0);} 50% { transform: translateY(-8px);} 100% { transform: translateY(0);} }
        .group:hover svg { animation: floaty 2s ease-in-out infinite; }
      `}</style>
    </div>
  );
};

export default LoadingScreen;
