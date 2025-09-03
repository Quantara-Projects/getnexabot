import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Check, Sparkles, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const PricingSection = () => {
  const navigate = useNavigate();

  const betaFeatures = [
    'Unlimited conversations',
    'Website chat widget',
    'WhatsApp integration (coming soon)',
    'Messenger integration (coming soon)',
    'Lead capture & notifications',
    'Custom AI training',
    'Analytics dashboard',
    'Email support',
    'No setup fees'
  ];

  const futurePlans = [
    {
      name: 'Starter',
      price: '$29',
      description: 'Perfect for small businesses',
      features: ['1,000 conversations/month', 'Website integration', 'Email support']
    },
    {
      name: 'Professional',
      price: '$79',
      description: 'For growing businesses',
      features: ['5,000 conversations/month', 'All integrations', 'Priority support', 'Advanced analytics']
    },
    {
      name: 'Enterprise',
      price: 'Custom',
      description: 'For large organizations',
      features: ['Unlimited conversations', 'Custom integrations', 'Dedicated support', 'White-label option']
    }
  ];

  return (
    <section id="pricing" className="py-20 bg-gradient-to-br from-secondary/20 to-background">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16 animate-fade-in-up">
          <Badge className="bg-green-100 text-green-700 border-green-200 mb-6">
            <Sparkles className="w-4 h-4 mr-2" />
            Beta Pricing - Limited Time
          </Badge>
          
          <h2 className="text-4xl lg:text-5xl font-bold mb-6">
            Free During{' '}
            <span className="gradient-text">Beta</span>
          </h2>
          
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Get full access to all NexaBot features during our beta period. No payment required, no hidden fees.
          </p>
        </div>

        <div className="max-w-6xl mx-auto">
          {/* Beta Plan */}
          <div className="mb-16 animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
            <Card className="relative overflow-hidden border-2 border-green-200 shadow-xl">
              {/* Beta Badge */}
              <div className="absolute top-0 right-0 bg-green-500 text-white px-8 py-2 transform rotate-12 translate-x-6 translate-y-4">
                <span className="font-bold text-sm">FREE BETA</span>
              </div>
              
              <CardHeader className="text-center pb-2">
                <div className="flex justify-center mb-4">
                  <div className="w-20 h-20 bg-gradient-to-r from-green-500 to-green-600 rounded-3xl flex items-center justify-center">
                    <Sparkles className="w-10 h-10 text-white" />
                  </div>
                </div>
                
                <CardTitle className="text-3xl font-bold">Beta Access Plan</CardTitle>
                <div className="text-6xl font-bold text-green-600 my-4">
                  FREE
                  <span className="text-lg text-muted-foreground font-normal ml-2">during beta</span>
                </div>
                <p className="text-muted-foreground text-lg">
                  Full access to all features while we perfect the platform
                </p>
              </CardHeader>
              
              <CardContent className="px-8 pb-8">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  {/* Features List */}
                  <div>
                    <h4 className="font-semibold mb-4 text-lg">Everything included:</h4>
                    <ul className="space-y-3">
                      {betaFeatures.map((feature, index) => (
                        <li key={index} className="flex items-center">
                          <Check className="w-5 h-5 text-green-600 mr-3 flex-shrink-0" />
                          <span>{feature}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  
                  {/* Benefits */}
                  <div className="bg-green-50 rounded-2xl p-6">
                    <h4 className="font-semibold mb-4 text-lg text-green-800">Beta Benefits:</h4>
                    <ul className="space-y-3 text-green-700">
                      <li className="flex items-center">
                        <Check className="w-5 h-5 mr-3 flex-shrink-0" />
                        <span>Lifetime 50% discount when we launch</span>
                      </li>
                      <li className="flex items-center">
                        <Check className="w-5 h-5 mr-3 flex-shrink-0" />
                        <span>Priority feature requests</span>
                      </li>
                      <li className="flex items-center">
                        <Check className="w-5 h-5 mr-3 flex-shrink-0" />
                        <span>Direct line to founders</span>
                      </li>
                      <li className="flex items-center">
                        <Check className="w-5 h-5 mr-3 flex-shrink-0" />
                        <span>Case study opportunities</span>
                      </li>
                    </ul>
                  </div>
                </div>
                
                <div className="mt-8 text-center">
                  <Button 
                    size="lg"
                    className="h-14 px-8 bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white text-lg shadow-glow"
                    onClick={() => navigate('/signup')}
                  >
                    Get Free Beta Access
                    <ArrowRight className="w-5 h-5 ml-2" />
                  </Button>
                  
                  <p className="text-sm text-muted-foreground mt-4">
                    No credit card required • Cancel anytime • Join 500+ beta users
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Future Pricing */}
          <div className="animate-fade-in-up" style={{ animationDelay: '0.4s' }}>
            <div className="text-center mb-8">
              <h3 className="text-2xl font-bold mb-4">Future Pricing Plans</h3>
              <p className="text-muted-foreground">
                These plans will be available when we launch. Beta users get 50% off for life!
              </p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {futurePlans.map((plan, index) => (
                <Card 
                  key={index} 
                  className="relative overflow-hidden opacity-60 hover:opacity-80 transition-smooth"
                >
                  {/* Coming Soon overlay */}
                  <div className="absolute inset-0 bg-white/80 backdrop-blur-[1px] flex items-center justify-center z-10">
                    <Badge variant="secondary" className="text-lg px-4 py-2">
                      Coming Soon
                    </Badge>
                  </div>
                  
                  <CardHeader className="text-center">
                    <CardTitle className="text-xl">{plan.name}</CardTitle>
                    <div className="text-4xl font-bold text-muted-foreground">
                      {plan.price}
                      {plan.price !== 'Custom' && <span className="text-sm font-normal">/month</span>}
                    </div>
                    <p className="text-muted-foreground">{plan.description}</p>
                  </CardHeader>
                  
                  <CardContent>
                    <ul className="space-y-2">
                      {plan.features.map((feature, idx) => (
                        <li key={idx} className="flex items-center text-sm">
                          <Check className="w-4 h-4 text-muted-foreground mr-2 flex-shrink-0" />
                          <span className="text-muted-foreground">{feature}</span>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default PricingSection;