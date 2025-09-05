import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Globe, Slack, Github, FileText, MessagesSquare, PlugZap, Zap } from 'lucide-react';
import { Reveal } from '@/hooks/use-in-view';

const IntegrationsSection = () => {
  return (
    <section id="integrations" className="py-20 bg-gradient-to-br from-secondary/20 to-background">
      <div className="container mx-auto px-6">
        <Reveal className="text-center mb-12">
          <h2 className="text-4xl lg:text-5xl font-bold mb-4">Integrations</h2>
          <p className="text-xl text-muted-foreground">NexaBot works where you work. Bring intelligent assistance into your daily tools.</p>
        </Reveal>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Reveal>
            <Card className="h-full">
              <CardHeader>
                <CardTitle>Current Integrations</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-muted-foreground">
                <div className="flex items-start space-x-3"><Globe className="w-5 h-5 text-primary mt-0.5" /><p>Website Chat Widget – Add a smart AI assistant to your website in minutes.</p></div>
                <div className="flex items-start space-x-3"><Slack className="w-5 h-5 text-primary mt-0.5" /><p>Slack & Discord – Bring AI into team communication.</p></div>
                <div className="flex items-start space-x-3"><FileText className="w-5 h-5 text-primary mt-0.5" /><p>Google Docs & Notion – Use NexoBot as your editor and idea generator.</p></div>
                <div className="flex items-start space-x-3"><Github className="w-5 h-5 text-primary mt-0.5" /><p>GitHub & GitLab – Get coding help and explanations inside your repos.</p></div>
              </CardContent>
            </Card>
          </Reveal>

          <Reveal>
            <Card className="h-full">
              <CardHeader>
                <CardTitle>Coming Soon</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-muted-foreground">
                <div className="flex items-start space-x-3"><MessagesSquare className="w-5 h-5 text-primary mt-0.5" /><p>WhatsApp & Messenger Bots – Automate customer engagement.</p></div>
                <div className="flex items-start space-x-3"><PlugZap className="w-5 h-5 text-primary mt-0.5" /><p>CRM Systems – Enrich customer data with AI insights.</p></div>
                <div className="flex items-start space-x-3"><Zap className="w-5 h-5 text-primary mt-0.5" /><p>Zapier Integration – Connect NexoBot with 3,000+ apps.</p></div>
              </CardContent>
            </Card>
          </Reveal>
        </div>
      </div>
    </section>
  );
};

export default IntegrationsSection;
