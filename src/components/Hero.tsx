import { Button } from '@/components/ui/button';
import { ArrowRight, Bot, MessageCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import Navigation from './Navigation';

const Hero = () => {
  const navigate = useNavigate();

  return (
    <>
      <Navigation />
      <section id="hero" className="relative min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-secondary/10 to-background overflow-hidden pt-16">
      {/* Background Elements */}
      <div className="absolute inset-0">
        <div className="absolute -top-40 -right-40 w-80 h-80 rounded-full bg-gradient-to-r from-primary/20 to-violet-500/20 blur-3xl animate-float"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 rounded-full bg-gradient-to-r from-blue-500/20 to-primary/20 blur-3xl animate-float" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 rounded-full bg-gradient-to-r from-primary/10 to-violet-500/10 blur-3xl"></div>
      </div>

      <div className="container mx-auto px-6 py-20 relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          {/* Left Content */}
          <div className="text-center lg:text-left animate-fade-in-up">
            <div className="inline-flex items-center px-4 py-2 bg-primary/10 rounded-full text-primary font-medium text-sm mb-6">
              <Bot className="w-4 h-4 mr-2" />
              Beta Access Now Available
            </div>
            
            <h1 className="text-5xl lg:text-6xl font-bold mb-6 leading-tight">
              AI Chatbots That{' '}
              <span className="gradient-text">
                Reply Instantly
              </span>
              , Anytime
            </h1>
            
            <p className="text-xl text-muted-foreground mb-8 leading-relaxed">
              NexaBot integrates with your website, WhatsApp, and Messenger to give customers instant answers, capture leads, and provide 24/7 support.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start">
              <Button 
                size="lg" 
                className="h-14 px-8 bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white shadow-glow transition-smooth text-lg"
                onClick={() => navigate('/signup')}
              >
                Get Started Free – Beta Access
                <ArrowRight className="w-5 h-5 ml-2" />
              </Button>
              
              <Button 
                variant="outline" 
                size="lg" 
                className="h-14 px-8 border-2 hover:bg-secondary/50 transition-smooth text-lg"
              >
                Watch Demo
              </Button>
            </div>
            
            <div className="flex items-center justify-center lg:justify-start mt-8 text-sm text-muted-foreground">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span>Free during beta • No credit card required</span>
              </div>
            </div>
          </div>

          {/* Right Content - Chat Animation */}
          <div className="relative animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
            <div className="relative bg-white rounded-3xl shadow-xl p-6 mx-auto max-w-sm">
              {/* Chat Header */}
              <div className="flex items-center justify-between pb-4 border-b">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-gradient-to-r from-primary to-violet-600 rounded-full flex items-center justify-center">
                    <Bot className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-sm">NexaBot</h3>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                      <span className="text-xs text-muted-foreground">Always online</span>
                    </div>
                  </div>
                </div>
                <MessageCircle className="w-5 h-5 text-muted-foreground" />
              </div>

              {/* Chat Messages */}
              <div className="space-y-4 py-4">
                {/* User Message */}
                <div className="flex justify-end animate-fade-in-up" style={{ animationDelay: '0.5s' }}>
                  <div className="bg-primary text-white rounded-2xl rounded-br-md px-4 py-2 max-w-[80%] text-sm">
                    Hi, do you offer 24/7 support?
                  </div>
                </div>

                {/* Bot Typing - Shows first in loop */}
                <div className="flex justify-start animate-chat-loop-typing">
                  <div className="bg-secondary rounded-2xl rounded-bl-md px-4 py-3 max-w-[80%]">
                    <div className="typing-dots">
                      <span></span>
                      <span></span>
                      <span></span>
                    </div>
                  </div>
                </div>

                {/* Bot Response - Appears after typing */}
                <div className="flex justify-start animate-chat-loop-response">
                  <div className="bg-secondary rounded-2xl rounded-bl-md px-4 py-2 max-w-[80%] text-sm">
                    Yes! I'm available 24/7 to help you instantly. What can I assist you with today? 🚀
                  </div>
                </div>
              </div>

              {/* Chat Input */}
              <div className="pt-4 border-t">
                <div className="flex items-center space-x-2 bg-secondary/50 rounded-full px-4 py-2">
                  <span className="text-sm text-muted-foreground flex-1">Type a message...</span>
                  <div className="w-6 h-6 bg-primary rounded-full flex items-center justify-center">
                    <ArrowRight className="w-3 h-3 text-white" />
                  </div>
                </div>
              </div>
            </div>

            {/* Floating Elements */}
            <div className="absolute -top-4 -left-4 bg-green-100 text-green-700 px-3 py-1 rounded-full text-xs font-medium shadow-md animate-bounce-in" style={{ animationDelay: '3s' }}>
              ⚡ Instant Reply
            </div>
            <div className="absolute -bottom-4 -right-4 bg-blue-100 text-blue-700 px-3 py-1 rounded-full text-xs font-medium shadow-md animate-bounce-in" style={{ animationDelay: '3.5s' }}>
              🎯 Lead Captured
            </div>
          </div>
        </div>
      </div>
    </section>
    </>
  );
};

export default Hero;