import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ArrowRight, Upload, Link, Rocket, CheckCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const HowItWorks = () => {
  const navigate = useNavigate();
  
  const steps = [
    {
      step: 1,
      icon: Upload,
      title: 'Sign Up & Train',
      description: 'Create your account and upload FAQs or paste your website link. Our AI learns your business instantly.',
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      borderColor: 'border-blue-200'
    },
    {
      step: 2,
      icon: Link,
      title: 'Connect Channels',
      description: 'Integrate with your website, WhatsApp, and Messenger. One-click setup for all platforms.',
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      borderColor: 'border-green-200'
    },
    {
      step: 3,
      icon: Rocket,
      title: 'Go Live',
      description: 'Your AI chatbot starts providing instant replies 24/7. Watch leads and satisfaction soar.',
      color: 'text-purple-600',
      bgColor: 'bg-purple-50',
      borderColor: 'border-purple-200'
    }
  ];

  return (
    <section id="how-it-works" className="py-20 bg-secondary/20">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl lg:text-5xl font-bold mb-6">
            How NexaBot Works
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Get your AI chatbot up and running in just 3 simple steps. No technical expertise required.
          </p>
        </div>

        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-16">
            {steps.map((step, index) => (
              <div key={index} className="relative">
                <Card 
                  className={`group hover:shadow-xl transition-smooth animate-fade-in-up border-2 ${step.borderColor} hover:border-primary/50`}
                  style={{ animationDelay: `${index * 0.2}s` }}
                >
                  <CardContent className="p-8 text-center">
                    {/* Step Number */}
                    <div className="relative mb-6">
                      <div className={`w-16 h-16 ${step.bgColor} rounded-2xl flex items-center justify-center mx-auto group-hover:scale-110 transition-smooth`}>
                        <step.icon className={`w-8 h-8 ${step.color}`} />
                      </div>
                      <div className="absolute -top-2 -right-2 w-8 h-8 bg-gradient-to-r from-primary to-violet-600 rounded-full flex items-center justify-center text-white font-bold text-sm">
                        {step.step}
                      </div>
                    </div>
                    
                    <h3 className="text-xl font-bold mb-4">{step.title}</h3>
                    <p className="text-muted-foreground leading-relaxed mb-6">{step.description}</p>
                    
                    <div className="flex items-center justify-center">
                      <CheckCircle className="w-5 h-5 text-green-600 mr-2" />
                      <span className="text-sm font-medium text-green-600">Ready in minutes</span>
                    </div>
                  </CardContent>
                </Card>
                
                {/* Arrow connector (hidden on mobile) */}
                {index < steps.length - 1 && (
                  <div className="hidden lg:block absolute top-1/2 -right-4 transform -translate-y-1/2 z-10">
                    <ArrowRight className="w-8 h-8 text-primary" />
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Timeline visualization for mobile */}
          <div className="lg:hidden flex justify-center mb-12">
            <div className="flex items-center space-x-4">
              {steps.map((_, index) => (
                <div key={index} className="flex items-center">
                  <div className="w-3 h-3 bg-primary rounded-full"></div>
                  {index < steps.length - 1 && (
                    <div className="w-8 h-0.5 bg-primary/30 mx-2"></div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* CTA */}
          <div className="text-center animate-fade-in-up" style={{ animationDelay: '0.8s' }}>
            <Card className="inline-block p-8 bg-gradient-to-r from-primary/5 to-violet-500/5 border-primary/20">
              <CardContent className="p-0">
                <h3 className="text-2xl font-bold mb-4">Ready to Get Started?</h3>
                <p className="text-muted-foreground mb-6 max-w-md mx-auto">
                  Join hundreds of businesses already using NexaBot to provide instant customer support.
                </p>
                
                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                  <Button 
                    size="lg"
                    className="bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white shadow-glow"
                    onClick={() => navigate('/signup')}
                  >
                    Start Free Beta
                    <ArrowRight className="w-5 h-5 ml-2" />
                  </Button>
                  
                  <Button variant="outline" size="lg">
                    Schedule Demo
                  </Button>
                </div>
                
                <p className="text-xs text-muted-foreground mt-4">
                  No credit card required • Setup in under 5 minutes
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HowItWorks;