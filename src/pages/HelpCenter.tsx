import { ArrowLeft, LifeBuoy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate } from 'react-router-dom';

const HelpCenter = () => {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Button variant="ghost" onClick={() => navigate('/')} className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4 mr-2" /> Home
          </Button>
          <div className="flex items-center space-x-2">
            <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg"><LifeBuoy className="w-5 h-5 text-white" /></div>
            <h1 className="text-lg font-bold">Help Center</h1>
          </div>
        </div>
      </header>
      <div className="container mx-auto px-6 py-10">
        <Card>
          <CardHeader>
            <CardTitle>Help Center</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-muted-foreground">
            <p>The Help Center is your go-to resource for quick answers and tutorials.</p>
            <div>
              <h3 className="font-semibold mb-2">Popular Topics</h3>
              <ul className="list-disc pl-5 space-y-1">
                <li>Getting Started – Creating an account, setting up your first bot.</li>
                <li>Account & Billing – Managing subscriptions, invoices, and upgrades.</li>
                <li>Bot Training – Uploading documents and customizing your AI.</li>
                <li>Integrations – Adding NexaBot to Slack, Discord, or your website.</li>
                <li>Security & Privacy – How we protect your data.</li>
              </ul>
            </div>
            <p>If you don’t find your answer, our support team is one click away.</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default HelpCenter;
