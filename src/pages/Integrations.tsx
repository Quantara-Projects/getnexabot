import { ArrowLeft, Bot, Plug } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate } from 'react-router-dom';

const Integrations = () => {
  const navigate = useNavigate();
  const items = [
    { name: 'Website Chat', status: 'Available' },
    { name: 'WhatsApp Business API', status: 'Coming Soon' },
    { name: 'Facebook Messenger', status: 'Coming Soon' },
  ];
  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Button variant="ghost" onClick={() => navigate('/')} className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4 mr-2" /> Home
          </Button>
          <div className="flex items-center space-x-2">
            <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg"><Plug className="w-5 h-5 text-white" /></div>
            <h1 className="text-lg font-bold">Integrations</h1>
          </div>
        </div>
      </header>
      <div className="container mx-auto px-6 py-10 grid gap-6 md:grid-cols-2">
        {items.map((it) => (
          <Card key={it.name} className="animate-fade-in-up">
            <CardHeader>
              <CardTitle>{it.name}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">Status: {it.status}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default Integrations;
