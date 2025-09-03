import { ArrowLeft, Bot, Shield, Eye, Lock, FileText } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate } from 'react-router-dom';

const PrivacyPolicy = () => {
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
                <Shield className="w-5 h-5 text-white" />
              </div>
              <h1 className="text-lg sm:text-xl font-bold">Privacy Policy</h1>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 sm:px-6 py-8 sm:py-12 max-w-4xl">
        {/* Hero Section */}
        <div className="text-center mb-8 sm:mb-12">
          <div className="flex items-center justify-center mb-4">
            <div className="bg-gradient-to-r from-primary to-violet-600 p-3 rounded-2xl">
              <FileText className="w-8 h-8 text-white" />
            </div>
          </div>
          <h1 className="text-3xl sm:text-4xl font-bold mb-4">
            📜 Privacy Policy
          </h1>
          <div className="space-y-2 text-muted-foreground">
            <p><strong>Effective Date:</strong> Processing</p>
            <p><strong>Company Name:</strong> NexaBot</p>
            <p><strong>Website:</strong> www.nexabot.com</p>
          </div>
        </div>

        <div className="space-y-8">
          {/* Introduction */}
          <Card className="animate-fade-in-up">
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <Shield className="w-5 h-5 mr-2 text-primary" />
                1. Introduction
              </CardTitle>
            </CardHeader>
            <CardContent className="prose prose-sm max-w-none">
              <p className="text-muted-foreground leading-relaxed">
                NexaBot respects your privacy and is committed to protecting your personal information. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our website and services.
              </p>
              <p className="text-muted-foreground leading-relaxed mt-4">
                By accessing or using NexaBot, you agree to the terms of this Privacy Policy. If you do not agree, please discontinue use of our services.
              </p>
            </CardContent>
          </Card>

          {/* Information We Collect */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <Eye className="w-5 h-5 mr-2 text-primary" />
                2. Information We Collect
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div>
                  <h3 className="font-semibold mb-3 text-lg">a. Information You Provide</h3>
                  <ul className="space-y-2 text-muted-foreground pl-4">
                    <li>• Name, email address, and business details (when creating an account).</li>
                    <li>• Uploaded files, documents, FAQs, or website links (to train your chatbot).</li>
                    <li>• Payment details (in the future, when paid plans are available).</li>
                  </ul>
                </div>

                <div>
                  <h3 className="font-semibold mb-3 text-lg">b. Information Collected Automatically</h3>
                  <ul className="space-y-2 text-muted-foreground pl-4">
                    <li>• IP address, browser type, operating system.</li>
                    <li>• Usage data (e.g., pages visited, chatbot interactions, error logs).</li>
                  </ul>
                </div>

                <div>
                  <h3 className="font-semibold mb-3 text-lg">c. Third-Party Integrations</h3>
                  <p className="text-muted-foreground">
                    If you connect WhatsApp, Messenger, or other services, we may process related communication data in order to provide chatbot functionality.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* How We Use Your Information */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <Bot className="w-5 h-5 mr-2 text-primary" />
                3. How We Use Your Information
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">We use your information to:</p>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• Provide and maintain NexaBot services.</li>
                <li>• Train and deploy AI chatbots for your business.</li>
                <li>• Improve our platform and user experience.</li>
                <li>• Send service-related updates and notifications.</li>
                <li>• Ensure security and prevent fraud.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Sharing of Information */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
            <CardHeader>
              <CardTitle className="text-xl">4. Sharing of Information</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">We do not sell your data. We only share information with:</p>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• <strong>Service Providers:</strong> Hosting, analytics, payment processors.</li>
                <li>• <strong>Legal Compliance:</strong> If required by law or government request.</li>
                <li>• <strong>Business Transfers:</strong> In case of merger, acquisition, or sale of assets.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Data Storage & Security */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.4s' }}>
            <CardHeader>
              <CardTitle className="flex items-center text-xl">
                <Lock className="w-5 h-5 mr-2 text-primary" />
                5. Data Storage & Security
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• Your data is stored securely with encryption.</li>
                <li>• Access is restricted to authorized personnel only.</li>
                <li>• While we implement best practices, no method of storage or transmission is 100% secure.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Your Rights */}
          <Card className="animate-fade-in-up" style={{ animationDelay: '0.5s' }}>
            <CardHeader>
              <CardTitle className="text-xl">6. Your Rights</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">Depending on your jurisdiction (e.g., GDPR, CCPA), you may have the right to:</p>
              <ul className="space-y-2 text-muted-foreground pl-4">
                <li>• Access, correct, or delete your personal data.</li>
                <li>• Request data portability.</li>
                <li>• Opt-out of marketing communications.</li>
                <li>• Withdraw consent at any time.</li>
              </ul>
            </CardContent>
          </Card>

          {/* Additional Sections */}
          <div className="grid sm:grid-cols-2 gap-6">
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.6s' }}>
              <CardHeader>
                <CardTitle className="text-lg">7. Cookies & Tracking</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground mb-3">NexaBot uses cookies to:</p>
                <ul className="space-y-1 text-muted-foreground text-sm pl-4">
                  <li>• Improve user experience.</li>
                  <li>• Analyze usage patterns.</li>
                  <li>• Remember login sessions.</li>
                </ul>
                <p className="text-muted-foreground text-sm mt-3">
                  You can manage cookie settings in your browser.
                </p>
              </CardContent>
            </Card>

            <Card className="animate-fade-in-up" style={{ animationDelay: '0.7s' }}>
              <CardHeader>
                <CardTitle className="text-lg">8. Children's Privacy</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground text-sm">
                  NexaBot is not intended for children under 13 (or 16 in EU). We do not knowingly collect data from minors.
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Changes & Contact */}
          <div className="grid sm:grid-cols-2 gap-6">
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.8s' }}>
              <CardHeader>
                <CardTitle className="text-lg">9. Changes to Privacy Policy</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground text-sm">
                  We may update this Privacy Policy from time to time. The updated version will be posted with a new effective date.
                </p>
              </CardContent>
            </Card>

            <Card className="animate-fade-in-up" style={{ animationDelay: '0.9s' }}>
              <CardHeader>
                <CardTitle className="text-lg">10. Contact Us</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground text-sm mb-2">
                  For questions, please contact us at:
                </p>
                <p className="text-primary font-medium">📧 support@nexabot.com</p>
              </CardContent>
            </Card>
          </div>

          {/* Footer */}
          <Card className="bg-gradient-to-r from-primary/10 to-violet-600/10 border-primary/20 animate-fade-in-up" style={{ animationDelay: '1s' }}>
            <CardContent className="p-6 text-center">
              <p className="text-muted-foreground text-sm">
                © 2025 NexaBot. All Rights Reserved. Unauthorized use, duplication, or reproduction of NexaBot services, features, or branding is strictly prohibited.
              </p>
            </CardContent>
          </Card>
        </div>

        {/* CTA Section */}
        <div className="text-center mt-12 animate-fade-in-up" style={{ animationDelay: '1.1s' }}>
          <h2 className="text-2xl font-bold mb-4">Questions About Our Privacy Policy?</h2>
          <p className="text-muted-foreground mb-6">
            Contact our support team for clarification on any privacy matters.
          </p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Button 
              onClick={() => navigate('/contact')}
              variant="outline"
              className="hover:bg-primary hover:text-white"
            >
              Contact Support
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

export default PrivacyPolicy;