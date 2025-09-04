import { ArrowLeft, Cookie } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate } from 'react-router-dom';

const CookiePolicy = () => {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Button variant="ghost" onClick={() => navigate('/')} className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4 mr-2" /> Home
          </Button>
          <div className="flex items-center space-x-2">
            <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg"><Cookie className="w-5 h-5 text-white" /></div>
            <h1 className="text-lg font-bold">Cookie Policy</h1>
          </div>
        </div>
      </header>
      <div className="container mx-auto px-6 py-10">
        <Card>
          <CardHeader>
            <CardTitle>Cookie Policy</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-muted-foreground">
            <p>We use cookies to enhance your browsing experience and provide personalized services.</p>
            <div>
              <h3 className="font-semibold mb-2">Types of Cookies</h3>
              <ul className="list-disc pl-5 space-y-1">
                <li>Essential Cookies – Required for login and core functionality.</li>
                <li>Performance Cookies – Help us understand usage patterns and improve the platform.</li>
                <li>Functional Cookies – Remember preferences like language and theme.</li>
                <li>Analytics Cookies – Collect anonymized statistics to optimize our services.</li>
              </ul>
            </div>
            <p>You can adjust or revoke cookie permissions anytime in Settings. We do not sell your personal data.</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default CookiePolicy;
