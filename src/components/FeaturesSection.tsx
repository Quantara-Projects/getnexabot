import { Bot, FileText, GraduationCap, MessageSquare, Shield, Palette } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Reveal } from '@/hooks/use-in-view';

const features = [
  { icon: MessageSquare, title: 'AI Chat Assistant', desc: 'Have natural conversations to brainstorm, write, or debug.' },
  { icon: FileText, title: 'Document Analyzer', desc: 'Upload files or paste text and receive structured insights.' },
  { icon: GraduationCap, title: 'Custom Bot Training', desc: 'Train your NexoBot with your company’s knowledge base.' },
  { icon: MessageSquare, title: 'Omnichannel Support', desc: 'Deploy across website, Slack, WhatsApp, and more.' },
  { icon: Shield, title: 'Security by Design', desc: 'End-to-end encryption, GDPR compliance, strict data policies.' },
  { icon: Palette, title: 'Customizable UI', desc: 'Personalize appearance, greeting, and personality.' },
];

const FeaturesSection = () => {
  return (
    <section id="features" className="py-20 bg-background">
      <div className="container mx-auto px-6">
        <Reveal className="text-center mb-12">
          <h2 className="text-4xl lg:text-5xl font-bold mb-4">Features</h2>
          <p className="text-xl text-muted-foreground">NexoBot isn’t just an AI chatbot—it’s a platform designed to adapt to your workflow.</p>
        </Reveal>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((f, i) => (
            <Reveal key={i}>
              <Card className="h-full">
                <CardHeader className="flex flex-row items-center space-x-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center">
                    <f.icon className="w-5 h-5" />
                  </div>
                  <CardTitle>{f.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground">{f.desc}</p>
                </CardContent>
              </Card>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
