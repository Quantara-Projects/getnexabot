import React from 'react';
import { Button } from '@/components/ui/button';

const QuantaraSection: React.FC = () => {
  return (
    <section className="py-20 bg-gradient-to-br from-background to-secondary/10">
      <div className="container mx-auto px-6 text-center">
        <div className="max-w-3xl mx-auto bg-white/90 rounded-2xl p-8 shadow-lg">
          <h2 className="text-3xl sm:text-4xl font-bold mb-4">Quantara Corp</h2>
          <p className="text-lg text-muted-foreground mb-6">Visit the official Quantara website to learn more about their products and services.</p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <a href="https://quantara.netlify.app" target="_blank" rel="noopener noreferrer">
              <Button className="bg-gradient-to-r from-primary to-violet-600 text-white">Visit Quantara (quantara.netlify.app)</Button>
            </a>
            <a href="https://getnexabot.netlify.app" target="_blank" rel="noopener noreferrer">
              <Button variant="outline">Confirmation Page (getnexabot.netlify.app)</Button>
            </a>
          </div>
          <p className="text-sm text-muted-foreground mt-4">Main domain: <a href="https://quantara.com" className="text-primary hover:underline">quantara.com</a></p>
        </div>
      </div>
    </section>
  );
};

export default QuantaraSection;
