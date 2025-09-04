import { ArrowLeft, Bot, Shield, FileCheck, AlertTriangle, Gavel } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useNavigate } from 'react-router-dom';

const Terms = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center space-x-4">
            <Button 
              variant="ghost" 
              onClick={() => navigate('/')}
              className="text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Home
            </Button>
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg">
                <Gavel className="w-5 h-5 text-white" />
              </div>
              <h1 className="text-lg sm:text-xl font-bold">Terms of Service</h1>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 sm:px-6 py-8 sm:py-12 max-w-4xl">
        {/* Hero Section */}
        <div className="text-center mb-8 sm:mb-12">
          <div className="flex items-center justify-center mb-4">
            <div className="bg-gradient-to-r from-primary to-violet-600 p-3 rounded-2xl">
              <FileCheck className="w-8 h-8 text-white" />
            </div>
          </div>
          <h1 className="text-3xl sm:text-4xl font-bold mb-4">
            📜 Terms of Service (NexaBot)
          </h1>
          <div className="space-y-2 text-muted-foreground">
            <p><strong>Effective Date:</strong> Processing</p>
            <p><strong>Company Name:</strong> NexaBot</p>
            <p><strong>Website:</strong> www.nexabot.com</p>
          </div>
        </div>

        <div className="space-y-8">
          {/* Acceptance of Terms */}
          <Card className="animate-fade-in-up">
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <FileCheck className="w-5 h-5 mr-2 text-primary" />
                1. Acceptance of Terms
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground leading-relaxed">
                By accessing or using NexaBot, you agree to these Terms of Service ("Terms"). If you do not agree, do not use NexaBot.
              </p>
            </CardContent>
          </Card>

          {/* Services Provided */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <Bot className="w-5 h-5 mr-2 text-primary" />
                2. Services Provided
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground leading-relaxed">
                NexaBot offers AI-powered chatbot and voice assistant solutions ("Services") for businesses to automate customer support and lead capture.
              </p>
            </CardContent>
          </Card>

          {/* Beta Disclaimer */}
          <Card className="animate-fade-in-up border-orange-200 bg-orange-50/50" style={{ animationDelay: '0.2s' }}>
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <AlertTriangle className="w-5 h-5 mr-2 text-orange-600" />
                3. Beta Disclaimer
                <Badge variant="outline" className="ml-2 text-orange-600 border-orange-600">Important</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• NexaBot is currently in Beta and provided free of charge.</li>
                <li>• Features may change, break, or be discontinued at any time.</li>
                <li>• We do not guarantee uninterrupted service during Beta.</li>
              </ul>
            </CardContent>
          </Card>

          {/* User Accounts */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
            <CardHeader>
              <CardTitle className="text-xl">4. User Accounts</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• You must provide accurate and truthful information.</li>
                <li>• You are responsible for maintaining the confidentiality of your login credentials.</li>
                <li>• You agree not to share your account with unauthorized users.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Acceptable Use */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.4s' }}>
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <Shield className="w-5 h-5 mr-2 text-primary" />
                5. Acceptable Use
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">You agree not to:</p>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• Use NexaBot for illegal, harmful, or abusive purposes.</li>
                <li>• Upload malicious content (viruses, malware, harmful code).</li>
                <li>• Attempt to hack, reverse engineer, or disrupt our systems.</li>
                <li>• Use NexaBot to impersonate another person or entity.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Intellectual Property */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.5s' }}>
            <CardHeader>
              <CardTitle className="text-xl">6. Intellectual Property</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• All content, features, trademarks, and services of NexaBot are owned by NexaBot © 2025.</li>
                <li>• You may not copy, reproduce, or resell our services or branding.</li>
                <li>• NexaBot grants you a limited, non-transferable license to use the Services.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Payment Terms */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.6s' }}>
            <CardHeader>
              <CardTitle className="text-xl">7. Payment Terms (Future)</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• While Beta is free, future services may require payment.</li>
                <li>• Pricing and billing details will be announced upon official launch.</li>
                <li>• Non-payment may result in suspension of services.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Data & Privacy */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.7s' }}>
            <CardHeader>
              <CardTitle className="text-xl">8. Data & Privacy</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Your use of NexaBot is also governed by our{' '}
                <button 
                  onClick={() => navigate('/privacy-policy')}
                  className="text-primary hover:underline font-medium"
                >
                  Privacy Policy
                </button>.
              </p>
            </CardContent>
          </Card>

          {/* Service Availability */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.8s' }}>
            <CardHeader>
              <CardTitle className="text-xl">9. Service Availability</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• NexaBot aims for high uptime but does not guarantee uninterrupted service.</li>
                <li>• We may suspend or terminate services for maintenance, updates, or legal reasons.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Limitation of Liability */}
          <Card className="animate-fade-in-up border-red-200 bg-red-50/50" style={{ animationDelay: '0.9s' }}>
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <AlertTriangle className="w-5 h-5 mr-2 text-red-600" />
                10. Limitation of Liability
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• NexaBot is provided "as is" and "as available."</li>
                <li>• We are not liable for lost profits, lost data, or indirect damages arising from use of the Services.</li>
                <li>• Our total liability will not exceed the amount you paid to us in the last 6 months (currently $0 in Beta).</li>
              </ul>
            </CardContent>
          </Card>

          {/* Additional Terms */}
          <div className="grid sm:grid-cols-2 gap-6">
            <Card className="animate-fade-in-up" style={{ animationDelay: '1s' }}>
              <CardHeader>
                <CardTitle className="text-lg">11. Termination</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-muted-foreground text-sm pl-4">
                  <li>• We may suspend or terminate your account for violation of these Terms.</li>
                  <li>• You may terminate your account at any time.</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="animate-fade-in-up" style={{ animationDelay: '1.1s' }}>
              <CardHeader>
                <CardTitle className="text-lg">12. Governing Law</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground text-sm">
                  These Terms shall be governed by and construed in accordance with the laws of [Insert Country/State].
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Changes to Terms */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '1.2s' }}>
            <CardHeader>
              <CardTitle className="text-xl">13. Changes to Terms</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                We may update these Terms at any time. Continued use of NexaBot means you accept the updated Terms.
              </p>
            </CardContent>
          </Card>

          {/* Footer */}
          <Card className="bg-gradient-to-r from-primary/10 to-violet-600/10 border-primary/20 animate-fade-in-up" style={{ animationDelay: '1.3s' }}>
            <CardContent className="p-6 text-center">
              <p className="text-muted-foreground text-sm">
                © 2025 NexaBot. All Rights Reserved. Unauthorized use, duplication, or reproduction of NexaBot's services, code, or branding is strictly prohibited.
              </p>
            </CardContent>
          </Card>
        </div>

        {/* CTA Section */}
        <div className="text-center mt-12 animate-fade-in-up" style={{ animationDelay: '1.4s' }}>
          <h2 className="text-2xl font-bold mb-4">Ready to Accept Our Terms?</h2>
          <p className="text-muted-foreground mb-6">
            Start building your AI chatbot today with our free beta access.
          </p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Button 
              onClick={() => navigate('/contact')}
              variant="outline"
              className="hover:bg-primary hover:text-white"
            >
              Have Questions?
            </Button>
            <Button 
              onClick={() => navigate('/signup')}
              className="bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white"
            >
              Start Your Free Trial
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Terms;