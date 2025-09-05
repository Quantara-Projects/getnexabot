import { ArrowLeft, Code2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate } from 'react-router-dom';

const ApiDocs = () => {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Button variant="ghost" onClick={() => navigate('/')} className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4 mr-2" /> Home
          </Button>
          <div className="flex items-center space-x-2">
            <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg"><Code2 className="w-5 h-5 text-white" /></div>
            <h1 className="text-lg font-bold">API Documentation</h1>
          </div>
        </div>
      </header>
      <div className="container mx-auto px-6 py-10">
        <Card>
          <CardHeader>
            <CardTitle>API Docs</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-muted-foreground">
            <p>For developers who want to integrate NexaBot into their systems.</p>
            <div>
              <h3 className="font-semibold mb-2">API Highlights</h3>
              <ul className="list-disc pl-5 space-y-1">
                <li>Authentication – Secure via API keys or OAuth2.</li>
                <li>Endpoints: /chat, /train, /status</li>
                <li>Rate Limits – Free tier: 1000 requests/month, scalable plans available.</li>
                <li>Error Codes ��� Detailed responses with guidance.</li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold mb-2">Example Request</h3>
              <pre className="bg-secondary/30 p-3 rounded overflow-x-auto text-xs">
{`curl -X POST "https://api.nexabot.ai/chat" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"message": "Hello, bot!"}'`}
              </pre>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ApiDocs;
