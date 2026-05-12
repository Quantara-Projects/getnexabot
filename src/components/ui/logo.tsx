import React from "react";

interface LogoIconProps {
  className?: string;
  onClick?: () => void;
}

const LogoIcon: React.FC<LogoIconProps> = ({
  className = "w-8 h-8",
  onClick,
}) => (
  <svg
    viewBox="0 0 128 128"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
    onClick={onClick}
    style={onClick ? { cursor: "pointer" } : undefined}
  >
    <defs>
      <linearGradient id="nb_outer" x1="22" y1="10" x2="106" y2="118" gradientUnits="userSpaceOnUse">
        <stop stopColor="#10D6CE" />
        <stop offset="1" stopColor="#10B7B0" />
      </linearGradient>
      <linearGradient id="nb_inner" x1="36" y1="28" x2="92" y2="100" gradientUnits="userSpaceOnUse">
        <stop stopColor="#BFF6F4" />
        <stop offset="1" stopColor="#B2F2EE" />
      </linearGradient>
    </defs>

    {/* Outer hex */}
    <path
      d="M64 8L112 36V92L64 120L16 92V36L64 8Z"
      fill="url(#nb_outer)"
    />
    {/* Inner hex */}
    <path
      d="M64 26L98 46V82L64 102L30 82V46L64 26Z"
      fill="url(#nb_inner)"
    />

    {/* Circuit + plus */}
    <path
      d="M64 38V62"
      stroke="#12C8C1"
      strokeWidth="8"
      strokeLinecap="round"
    />
    <path
      d="M50 50H78"
      stroke="#12C8C1"
      strokeWidth="8"
      strokeLinecap="round"
    />
    <path
      d="M64 62V78"
      stroke="#12C8C1"
      strokeWidth="6"
      strokeLinecap="round"
    />
    <path
      d="M64 78L44 92"
      stroke="#12C8C1"
      strokeWidth="6"
      strokeLinecap="round"
    />
    <path
      d="M64 78L84 92"
      stroke="#12C8C1"
      strokeWidth="6"
      strokeLinecap="round"
    />
    <circle cx="64" cy="78" r="6" fill="#12C8C1" />
    <circle cx="44" cy="92" r="6" fill="#12C8C1" />
    <circle cx="84" cy="92" r="6" fill="#12C8C1" />
  </svg>
);

const LogoText = ({ className = "text-xl" }: { className?: string }) => (
  <span className={`font-bold tracking-tight ${className} text-foreground`}>
    NexaBot
  </span>
);

export { LogoIcon, LogoText };
