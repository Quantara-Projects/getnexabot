import { useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Bot, Send, User } from 'lucide-react';

const DemoSection = () => {
  const [messages, setMessages] = useState([
    {
      type: 'bot',
      message: "Hi! I'm NexaBot. Ask me anything about our services!"
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  const sampleQuestions = [
    "Do you offer 24/7 support?",
    "What are your pricing plans?",
    "How long does setup take?",
    "Can you integrate with WhatsApp?"
  ];

  const botResponses = {
    "Do you offer 24/7 support?": "Yes! NexaBot provides 24/7 instant support. I never sleep and respond within seconds to help your customers anytime.",
    "What are your pricing plans?": "We're currently in beta, so all features are FREE! When we launch, we'll have affordable plans starting at just $29/month.",
    "How long does setup take?": "Super fast! Most businesses are up and running in under 5 minutes. Just upload your FAQs or website link and you're ready to go!",
    "Can you integrate with WhatsApp?": "Absolutely! NexaBot works with your website, WhatsApp Business API, and Facebook Messenger - all from one dashboard."
  };

  const handleSendMessage = (message?: string) => {
    const messageToSend = message || inputValue;
    if (!messageToSend.trim()) return;

    // Add user message
    setMessages(prev => [...prev, { type: 'user', message: messageToSend }]);
    setInputValue('');
    setIsTyping(true);

    // Simulate bot response
    setTimeout(() => {
      setIsTyping(false);
      const response = botResponses[messageToSend as keyof typeof botResponses] || 
        "That's a great question! NexaBot learns from your business data to provide accurate, helpful responses to all customer inquiries. Want to see how it works? Sign up for free beta access!";
      
      setMessages(prev => [...prev, { type: 'bot', message: response }]);
    }, 1500);
  };

  return (
    <section id="demo" className="py-20 bg-background">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl lg:text-5xl font-bold mb-6">
            Try NexaBot{' '}
            <span className="gradient-text">Live Demo</span>
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Experience the power of instant AI responses. Ask any question and see how NexaBot would handle it for your business.
          </p>
        </div>

        <div className="max-w-4xl mx-auto">
          <Card className="shadow-2xl animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
            <CardContent className="p-0">
              <div className="grid grid-cols-1 lg:grid-cols-2">
                {/* Chat Interface */}
                <div className="p-6">
                  {/* Chat Header */}
                  <div className="flex items-center justify-between pb-4 border-b mb-6">
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 bg-gradient-to-r from-primary to-violet-600 rounded-full flex items-center justify-center">
                        <Bot className="w-5 h-5 text-white" />
                      </div>
                      <div>
                        <h3 className="font-semibold">NexaBot Demo</h3>
                        <div className="flex items-center space-x-2">
                          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                          <span className="text-xs text-muted-foreground">Online</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Chat Messages */}
                  <div className="space-y-4 mb-6 h-80 overflow-y-auto">
                    {messages.map((msg, index) => (
                      <div key={index} className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'} animate-fade-in-up`}>
                        <div className={`max-w-[80%] p-3 rounded-2xl ${
                          msg.type === 'user' 
                            ? 'bg-primary text-white rounded-br-md' 
                            : 'bg-secondary rounded-bl-md'
                        }`}>
                          <div className="flex items-start space-x-2">
                            {msg.type === 'bot' && <Bot className="w-4 h-4 mt-0.5 text-primary flex-shrink-0" />}
                            <p className="text-sm leading-relaxed">{msg.message}</p>
                            {msg.type === 'user' && <User className="w-4 h-4 mt-0.5 text-white/80 flex-shrink-0" />}
                          </div>
                        </div>
                      </div>
                    ))}
                    
                    {/* Typing indicator */}
                    {isTyping && (
                      <div className="flex justify-start animate-fade-in-up">
                        <div className="bg-secondary rounded-2xl rounded-bl-md p-3 max-w-[80%]">
                          <div className="flex items-center space-x-2">
                            <Bot className="w-4 h-4 text-primary" />
                            <div className="typing-dots">
                              <span></span>
                              <span></span>
                              <span></span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Chat Input */}
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2">
                      <Input
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value)}
                        placeholder="Type your question..."
                        className="flex-1"
                        onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                        disabled={isTyping}
                      />
                      <Button 
                        size="sm" 
                        onClick={() => handleSendMessage()}
                        disabled={!inputValue.trim() || isTyping}
                        className="bg-gradient-to-r from-primary to-violet-600"
                      >
                        <Send className="w-4 h-4" />
                      </Button>
                    </div>
                    
                    <div className="text-xs text-muted-foreground text-center">
                      This is a demo. Real NexaBot learns from your specific business data.
                    </div>
                  </div>
                </div>

                {/* Quick Questions */}
                <div className="bg-secondary/30 p-6 border-l">
                  <h4 className="font-semibold mb-4">Try these sample questions:</h4>
                  <div className="space-y-3">
                    {sampleQuestions.map((question, index) => (
                      <Button
                        key={index}
                        variant="outline"
                        className="w-full justify-start text-left h-auto p-3 text-sm hover:bg-primary/5"
                        onClick={() => handleSendMessage(question)}
                        disabled={isTyping}
                      >
                        {question}
                      </Button>
                    ))}
                  </div>
                  
                  <div className="mt-6 p-4 bg-primary/5 rounded-lg">
                    <div className="flex items-start space-x-3">
                      <Bot className="w-5 h-5 text-primary mt-0.5" />
                      <div className="text-sm">
                        <p className="font-medium mb-1">Pro Tip:</p>
                        <p className="text-muted-foreground">
                          NexaBot learns from YOUR business data, making responses even more accurate and personalized for your customers.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
};

export default DemoSection;