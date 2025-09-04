import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Globe, MessageSquare, Smartphone } from 'lucide-react';
import { Reveal } from '@/hooks/use-in-view';

const items = [
  { icon: Globe, title: 'Website Chat', desc: 'Embed a modern chat widget on your site', badge: 'Available' },
  { icon: MessageSquare, title: 'WhatsApp', desc: 'Business API integration', badge: 'Coming Soon' },
  { icon: Smartphone, title: 'Messenger', desc: 'Facebook Pages integration', badge: 'Coming Soon' },
];

const IntegrationsSection = () => {
  return (
    <section id="integrations" className="py-20 bg-gradient-to-br from-secondary/20 to-background">
      <div className="container mx-auto px-6">
        <Reveal className="text-center mb-12">
          <h2 className="text-4xl lg:text-5xl font-bold mb-4">Integrations</h2>
          <p className="text-xl text-muted-foreground">Connect NexaBot to your preferred channels.</p>
        </Reveal>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {items.map((it, i) => (
            <Reveal key={i}>
              <Card className="h-full border-2 hover:border-primary transition-smooth">
                <CardHeader className="flex flex-row items-center space-x-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center">
                    <it.icon className="w-5 h-5" />
                  </div>
                  <CardTitle>{it.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground">{it.desc}</p>
                  <div className="mt-3 inline-block px-2 py-1 text-xs rounded bg-secondary">{it.badge}</div>
                </CardContent>
              </Card>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
};

export default IntegrationsSection;
