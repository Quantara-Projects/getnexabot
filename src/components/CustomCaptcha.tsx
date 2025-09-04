import React, { useState, useEffect, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { RefreshCw } from 'lucide-react';

interface CustomCaptchaProps {
  onVerify: (isValid: boolean) => void;
  resetTrigger?: number;
}

const CustomCaptcha: React.FC<CustomCaptchaProps> = ({ onVerify, resetTrigger }) => {
  const [captchaText, setCaptchaText] = useState('');
  const [userInput, setUserInput] = useState('');
  const [isVerified, setIsVerified] = useState(false);
  const [canvasData, setCanvasData] = useState('');

  const generateCaptcha = useCallback(() => {
    const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let result = '';
    for (let i = 0; i < 6; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setCaptchaText(result);
    setUserInput('');
    setIsVerified(false);
    onVerify(false);
  }, [onVerify]);

  const drawCaptcha = useCallback(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 60;
    const ctx = canvas.getContext('2d');
    
    if (!ctx) return;

    // Background with gradient
    const gradient = ctx.createLinearGradient(0, 0, 200, 60);
    gradient.addColorStop(0, '#f0f9ff');
    gradient.addColorStop(1, '#e0f2fe');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 200, 60);

    // Add noise lines
    for (let i = 0; i < 5; i++) {
      ctx.strokeStyle = `hsl(${Math.random() * 360}, 50%, 70%)`;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(Math.random() * 200, Math.random() * 60);
      ctx.lineTo(Math.random() * 200, Math.random() * 60);
      ctx.stroke();
    }

    // Draw text with random colors and positions
    ctx.font = 'bold 24px Arial';
    for (let i = 0; i < captchaText.length; i++) {
      ctx.fillStyle = `hsl(${Math.random() * 360}, 70%, 40%)`;
      const x = 20 + i * 25 + Math.random() * 10 - 5;
      const y = 35 + Math.random() * 10 - 5;
      ctx.save();
      ctx.translate(x, y);
      ctx.rotate((Math.random() - 0.5) * 0.4);
      ctx.fillText(captchaText[i], 0, 0);
      ctx.restore();
    }

    // Add noise dots
    for (let i = 0; i < 50; i++) {
      ctx.fillStyle = `hsl(${Math.random() * 360}, 50%, 50%)`;
      ctx.fillRect(Math.random() * 200, Math.random() * 60, 2, 2);
    }

    setCanvasData(canvas.toDataURL());
  }, [captchaText]);

  useEffect(() => {
    generateCaptcha();
  }, [generateCaptcha, resetTrigger]);

  useEffect(() => {
    if (captchaText) {
      drawCaptcha();
    }
  }, [captchaText, drawCaptcha]);

  const handleVerify = () => {
    const isValid = userInput.toLowerCase() === captchaText.toLowerCase();
    setIsVerified(isValid);
    onVerify(isValid);
    
    if (!isValid) {
      generateCaptcha();
    }
  };

  const handleRefresh = () => {
    generateCaptcha();
  };

  return (
    <div className="space-y-4 p-4 border rounded-lg bg-background">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-foreground">Security Verification</h3>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={handleRefresh}
          className="h-8 w-8 p-0"
        >
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>
      
      <div className="flex justify-center">
        {canvasData && (
          <img 
            src={canvasData} 
            alt="Captcha" 
            className="border rounded bg-white"
            draggable={false}
            style={{ userSelect: 'none' }}
          />
        )}
      </div>
      
      <div className="space-y-2">
        <Input
          type="text"
          placeholder="Enter the text shown above"
          value={userInput}
          onChange={(e) => setUserInput(e.target.value)}
          className={isVerified ? 'border-green-500' : ''}
          onKeyDown={(e) => e.key === 'Enter' && handleVerify()}
        />
        <Button
          type="button"
          onClick={handleVerify}
          className="w-full"
          disabled={!userInput.trim()}
        >
          Verify
        </Button>
      </div>
      
      {isVerified && (
        <p className="text-sm text-green-600 text-center">✓ Verification successful</p>
      )}
    </div>
  );
};

export default CustomCaptcha;