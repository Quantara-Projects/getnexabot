import { CheckCircle, Zap, Shield, LineChart, Puzzle, Sparkles } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Reveal } from '@/hooks/use-in-view';

const features = [
  { icon: Zap, title: 'Instant Replies', desc: 'AI responds to customers in milliseconds, 24/7.' },
  { icon: Shield, title: 'Secure by Design', desc: 'Best practices for data protection and privacy.' },
  { icon: LineChart, title: 'Actionable Analytics', desc: 'Track conversations, leads, and satisfaction.' },
  { icon: Puzzle, title: 'Easy Integrations', desc: 'Works with your website and channels.' },
  { icon: Sparkles, title: 'Custom Training', desc: 'Feed your FAQs, docs, and site content.' },
  { icon: CheckCircle, title: 'Lead Capture', desc: 'Collect emails and route complex issues.' },
];

const FeaturesSection = () => {
  return (
    <section id="features" className="py-20 bg-background">
      <div className="container mx-auto px-6">
        <Reveal className="text-center mb-12">
          <h2 className="text-4xl lg:text-5xl font-bold mb-4">Powerful Features</h2>
          <p className="text-xl text-muted-foreground">Everything you need to support customers at scale.</p>
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
