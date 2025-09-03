import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Bot, Clock, MessageSquare, Target, Zap } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const SolutionSection = () => {
  const navigate = useNavigate();
  
  const features = [
    {
      icon: Clock,
      title: '24/7 Instant Replies',
      description: 'Never miss a customer. NexaBot responds instantly, any time of day or night.',
      color: 'text-blue-600',
      bgColor: 'bg-blue-50'
    },
    {
      icon: MessageSquare,
      title: 'Multi-Channel Support',
      description: 'Website, WhatsApp, and Messenger integration in one powerful platform.',
      color: 'text-green-600',
      bgColor: 'bg-green-50'
    },
    {
      icon: Target,
      title: 'Lead Capture & Notifications',
      description: 'Automatically capture leads and notify your team when human help is needed.',
      color: 'text-purple-600',
      bgColor: 'bg-purple-50'
    },
    {
      icon: Zap,
      title: 'No Coding Required',
      description: 'Set up in minutes with our simple wizard. No technical skills needed.',
      color: 'text-orange-600',
      bgColor: 'bg-orange-50'
    }
  ];

  return (
    <section id="features" className="py-20 bg-background relative overflow-hidden">
      {/* Background Elements */}
      <div className="absolute inset-0">
        <div className="absolute top-20 right-0 w-72 h-72 bg-gradient-to-l from-primary/10 to-transparent rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 left-0 w-72 h-72 bg-gradient-to-r from-violet-500/10 to-transparent rounded-full blur-3xl"></div>
      </div>

      <div className="container mx-auto px-6 relative z-10">
        <div className="text-center mb-16 animate-fade-in-up">
          <div className="inline-flex items-center px-4 py-2 bg-green-100 text-green-700 rounded-full font-medium text-sm mb-6">
            <Bot className="w-4 h-4 mr-2" />
            The Solution is Here
          </div>
          
          <h2 className="text-4xl lg:text-5xl font-bold mb-6">
            NexaBot Fixes This{' '}
            <span className="gradient-text">Instantly</span>
          </h2>
          
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Transform your customer support with AI that never sleeps, never gets tired, and always provides accurate answers.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-6xl mx-auto mb-16">
          {features.map((feature, index) => (
            <Card 
              key={index} 
              className="group hover:shadow-xl transition-smooth animate-fade-in-up border-2 hover:border-primary/20"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <CardContent className="p-8">
                <div className="flex items-start space-x-4">
                  <div className={`w-12 h-12 ${feature.bgColor} rounded-xl flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-smooth`}>
                    <feature.icon className={`w-6 h-6 ${feature.color}`} />
                  </div>
                  
                  <div className="flex-1">
                    <h3 className="text-xl font-bold mb-3">{feature.title}</h3>
                    <p className="text-muted-foreground leading-relaxed">{feature.description}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* AI Bot Animation */}
        <div className="text-center animate-fade-in-up" style={{ animationDelay: '0.6s' }}>
          <Card className="inline-block p-8 bg-gradient-to-br from-primary/5 to-violet-500/5 border-primary/20">
            <CardContent className="p-0">
              <div className="flex items-center justify-center mb-6">
                <div className="relative">
                  <div className="w-20 h-20 bg-gradient-to-r from-primary to-violet-600 rounded-2xl flex items-center justify-center animate-float">
                    <Bot className="w-10 h-10 text-white" />
                  </div>
                  <div className="absolute -top-2 -right-2 w-6 h-6 bg-green-500 rounded-full flex items-center justify-center animate-pulse">
                    <div className="w-2 h-2 bg-white rounded-full"></div>
                  </div>
                </div>
              </div>
              
              <h3 className="text-2xl font-bold mb-2">AI That Responds Instantly</h3>
              <p className="text-muted-foreground mb-6 max-w-md mx-auto">
                Watch NexaBot handle customer inquiries in real-time, providing accurate answers and capturing leads automatically.
              </p>
              
              <Button 
                size="lg"
                className="bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white shadow-glow"
                onClick={() => navigate('/signup')}
              >
                See It In Action
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
};

export default SolutionSection;