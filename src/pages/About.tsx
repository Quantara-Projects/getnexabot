import { ArrowLeft, Bot, Users, Zap, Shield, Globe, MessageSquare } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { useNavigate } from 'react-router-dom';

const About = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center space-x-4">
            <Button 
              variant="ghost" 
              onClick={() => navigate('/')}
              className="text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Home
            </Button>
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg">
                <Bot className="w-5 h-5 text-white" />
              </div>
              <h1 className="text-lg sm:text-xl font-bold">NexaBot</h1>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 sm:px-6 py-8 sm:py-12">
        {/* Hero Section */}
        <div className="text-center mb-12 sm:mb-16">
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-6">
            About <span className="bg-gradient-to-r from-primary to-violet-600 bg-clip-text text-transparent">NexaBot</span>
          </h1>
          <p className="text-lg sm:text-xl text-muted-foreground max-w-3xl mx-auto leading-relaxed">
            We're revolutionizing customer support with AI-powered chatbots that never sleep, never get tired, and always provide instant, accurate responses to your customers.
          </p>
        </div>

        {/* Mission Section */}
        <Card className="mb-12 sm:mb-16 animate-fade-in-up">
          <CardContent className="p-6 sm:p-8 lg:p-12">
            <div className="grid lg:grid-cols-2 gap-8 lg:gap-12 items-center">
              <div>
                <h2 className="text-2xl sm:text-3xl font-bold mb-6">Our Mission</h2>
                <p className="text-muted-foreground text-base sm:text-lg leading-relaxed mb-6">
                  Every business deserves to provide exceptional customer support, regardless of size or budget. 
                  We believe that no customer inquiry should go unanswered, no lead should be lost due to slow response times, 
                  and no business should be limited by human availability.
                </p>
                <p className="text-muted-foreground text-base sm:text-lg leading-relaxed">
                  NexaBot makes enterprise-level AI customer support accessible to every business, 
                  from startups to established companies, enabling them to scale their customer service without scaling their costs.
                </p>
              </div>
              <div className="bg-gradient-to-br from-primary/10 to-violet-600/10 rounded-2xl p-6 sm:p-8">
                <div className="grid grid-cols-2 gap-4 sm:gap-6">
                  <div className="text-center">
                    <div className="bg-gradient-to-r from-primary to-violet-600 p-3 sm:p-4 rounded-2xl mx-auto w-fit mb-3">
                      <Zap className="w-6 h-6 sm:w-8 sm:h-8 text-white" />
                    </div>
                    <h3 className="font-bold text-lg sm:text-xl">Instant</h3>
                    <p className="text-sm text-muted-foreground">&lt; 1s Response</p>
                  </div>
                  <div className="text-center">
                    <div className="bg-gradient-to-r from-primary to-violet-600 p-3 sm:p-4 rounded-2xl mx-auto w-fit mb-3">
                      <Globe className="w-6 h-6 sm:w-8 sm:h-8 text-white" />
                    </div>
                    <h3 className="font-bold text-lg sm:text-xl">24/7</h3>
                    <p className="text-sm text-muted-foreground">Always Available</p>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Story Section */}
        <div className="grid lg:grid-cols-2 gap-8 lg:gap-16 mb-12 sm:mb-16">
          <div className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
            <h2 className="text-2xl sm:text-3xl font-bold mb-6">The Problem We Solve</h2>
            <div className="space-y-4 sm:space-y-6">
              <div className="flex items-start space-x-4">
                <div className="bg-red-100 p-2 rounded-lg flex-shrink-0">
                  <MessageSquare className="w-5 h-5 text-red-600" />
                </div>
                <div>
                  <h3 className="font-semibold mb-2">Lost Sales from Slow Responses</h3>
                  <p className="text-muted-foreground text-sm sm:text-base">
                    Studies show 67% of customers expect responses within 4 hours, but most businesses take 12+ hours to reply.
                  </p>
                </div>
              </div>
              <div className="flex items-start space-x-4">
                <div className="bg-orange-100 p-2 rounded-lg flex-shrink-0">
                  <Users className="w-5 h-5 text-orange-600" />
                </div>
                <div>
                  <h3 className="font-semibold mb-2">Overwhelmed Support Teams</h3>
                  <p className="text-muted-foreground text-sm sm:text-base">
                    80% of customer inquiries are repetitive questions that drain valuable human resources.
                  </p>
                </div>
              </div>
              <div className="flex items-start space-x-4">
                <div className="bg-blue-100 p-2 rounded-lg flex-shrink-0">
                  <Shield className="w-5 h-5 text-blue-600" />
                </div>
                <div>
                  <h3 className="font-semibold mb-2">After-Hours Abandonment</h3>
                  <p className="text-muted-foreground text-sm sm:text-base">
                    40% of customers contact businesses outside working hours, leading to missed opportunities.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
            <h2 className="text-2xl sm:text-3xl font-bold mb-6">Our Solution</h2>
            <Card className="bg-gradient-to-br from-green-50 to-emerald-50 border-green-200">
              <CardContent className="p-6 sm:p-8">
                <div className="space-y-4 sm:space-y-6">
                  <div className="flex items-start space-x-4">
                    <div className="bg-green-500 p-2 rounded-lg flex-shrink-0">
                      <Zap className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <h3 className="font-semibold mb-2">Instant AI Responses</h3>
                      <p className="text-muted-foreground text-sm sm:text-base">
                        Our AI responds in under 1 second, 24/7, ensuring no customer waits.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-4">
                    <div className="bg-green-500 p-2 rounded-lg flex-shrink-0">
                      <Bot className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <h3 className="font-semibold mb-2">Smart Lead Capture</h3>
                      <p className="text-muted-foreground text-sm sm:text-base">
                        When the AI can't answer, it smoothly captures leads and notifies your team.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-4">
                    <div className="bg-green-500 p-2 rounded-lg flex-shrink-0">
                      <Globe className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <h3 className="font-semibold mb-2">Multi-Channel Support</h3>
                      <p className="text-muted-foreground text-sm sm:text-base">
                        Works on your website, WhatsApp, and Messenger from day one.
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Team Section */}
        <Card className="mb-12 sm:mb-16 animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
          <CardContent className="p-6 sm:p-8 lg:p-12 text-center">
            <h2 className="text-2xl sm:text-3xl font-bold mb-6">Built by Entrepreneurs, for Entrepreneurs</h2>
            <p className="text-muted-foreground text-base sm:text-lg leading-relaxed max-w-4xl mx-auto mb-8">
              Our team consists of experienced entrepreneurs and AI engineers who understand the daily challenges 
              of running a business. We've experienced firsthand the frustration of losing customers due to slow 
              response times and the overwhelming nature of managing customer support while trying to grow a business.
            </p>
            <p className="text-muted-foreground text-base sm:text-lg leading-relaxed max-w-4xl mx-auto">
              That's why we built NexaBot - to give every business owner the peace of mind that comes with knowing 
              their customers are always taken care of, even when they're sleeping, in meetings, or focused on growing their business.
            </p>
          </CardContent>
        </Card>

        {/* CTA Section */}
        <div className="text-center animate-fade-in-up" style={{ animationDelay: '0.4s' }}>
          <h2 className="text-2xl sm:text-3xl font-bold mb-6">Ready to Transform Your Customer Support?</h2>
          <p className="text-muted-foreground text-base sm:text-lg mb-8 max-w-2xl mx-auto">
            Join thousands of businesses already using NexaBot to provide instant, 24/7 customer support.
          </p>
          <Button 
            onClick={() => navigate('/signup')}
            className="h-12 px-8 bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white font-semibold shadow-glow transition-smooth text-base sm:text-lg"
          >
            Start Your Free Beta Trial
          </Button>
        </div>
      </div>
    </div>
  );
};

export default About;