import { ArrowLeft, Bot, CheckCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate } from 'react-router-dom';

const Features = () => {
  const navigate = useNavigate();
  const features = [
    { title: '24/7 Instant Support', desc: 'AI answers customers immediately across channels.' },
    { title: 'Website Chat Widget', desc: 'Embed a modern, fast chat on your site.' },
    { title: 'Custom AI Training', desc: 'Train on your FAQs, docs, and website.' },
    { title: 'Lead Capture', desc: 'Collect emails and messages when needed.' },
    { title: 'Analytics Dashboard', desc: 'See conversations, trends, and performance.' },
    { title: 'Integrations', desc: 'Connect with WhatsApp, Messenger, and more.' },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Button variant="ghost" onClick={() => navigate('/')} className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4 mr-2" /> Home
          </Button>
          <div className="flex items-center space-x-2">
            <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg">
              <Bot className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-lg font-bold">Features</h1>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-10 grid gap-6 md:grid-cols-2">
        {features.map((f, i) => (
          <Card key={i} className="animate-fade-in-up">
            <CardHeader>
              <CardTitle className="flex items-center"><CheckCircle className="w-5 h-5 text-primary mr-2" />{f.title}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">{f.desc}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default Features;
