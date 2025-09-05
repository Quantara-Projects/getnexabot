import { ArrowLeft, Bot, Mail, MessageSquare, Phone, Clock, MapPin, Send } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useNavigate } from 'react-router-dom';
import { useState } from 'react';

const Contact = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    subject: '',
    message: ''
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // form submission handled server-side; do not log sensitive data in production.
  };

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
              <h1 className="text-lg sm:text-xl font-bold">Contact NexaBot</h1>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 sm:px-6 py-8 sm:py-12">
        {/* Hero Section */}
        <div className="text-center mb-12 sm:mb-16">
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-6">
            Get in <span className="bg-gradient-to-r from-primary to-violet-600 bg-clip-text text-transparent">Touch</span>
          </h1>
          <p className="text-lg sm:text-xl text-muted-foreground max-w-3xl mx-auto leading-relaxed">
            Have questions about NexaBot? Need help setting up your chatbot? We're here to help you succeed.
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-8 sm:gap-12">
          {/* Contact Form */}
          <div className="lg:col-span-2">
            <Card className="animate-fade-in-up">
              <CardHeader>
                <CardTitle className="text-xl sm:text-2xl">Send us a Message</CardTitle>
                <p className="text-muted-foreground">
                  Fill out the form below and we'll get back to you within 24 hours.
                </p>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div className="grid sm:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="name">Full Name *</Label>
                      <Input
                        id="name"
                        name="name"
                        type="text"
                        placeholder="John Doe"
                        value={formData.name}
                        onChange={handleChange}
                        required
                        className="transition-smooth focus:shadow-glow"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="email">Email Address *</Label>
                      <Input
                        id="email"
                        name="email"
                        type="email"
                        placeholder="john@company.com"
                        value={formData.email}
                        onChange={handleChange}
                        required
                        className="transition-smooth focus:shadow-glow"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="subject">Subject *</Label>
                    <Input
                      id="subject"
                      name="subject"
                      type="text"
                      placeholder="How can we help you?"
                      value={formData.subject}
                      onChange={handleChange}
                      required
                      className="transition-smooth focus:shadow-glow"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="message">Message *</Label>
                    <Textarea
                      id="message"
                      name="message"
                      placeholder="Tell us more about your needs, questions, or how we can help you..."
                      value={formData.message}
                      onChange={handleChange}
                      required
                      rows={6}
                      className="transition-smooth focus:shadow-glow resize-none"
                    />
                  </div>

                  <Button 
                    type="submit"
                    className="w-full h-12 bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white font-semibold shadow-glow transition-smooth"
                  >
                    <Send className="w-4 h-4 mr-2" />
                    Send Message
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>

          {/* Contact Info */}
          <div className="space-y-6">
            {/* Contact Methods */}
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
              <CardHeader>
                <CardTitle className="text-lg">Contact Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-start space-x-3">
                  <div className="bg-primary/10 p-2 rounded-lg flex-shrink-0">
                    <Mail className="w-4 h-4 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-sm">Email Support</h3>
                    <p className="text-muted-foreground text-sm">support@nexabot.ai</p>
                    <p className="text-xs text-muted-foreground">24-48 hour response time</p>
                    <p className="text-muted-foreground text-sm mt-2">business@nexabot.ai • press@nexabot.ai</p>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <div className="bg-green-100 p-2 rounded-lg flex-shrink-0">
                    <MessageSquare className="w-4 h-4 text-green-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-sm">Live Chat</h3>
                    <p className="text-muted-foreground text-sm">Available on our website</p>
                    <p className="text-xs text-muted-foreground">Instant response</p>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <div className="bg-blue-100 p-2 rounded-lg flex-shrink-0">
                    <Phone className="w-4 h-4 text-blue-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-sm">Phone Support</h3>
                    <p className="text-muted-foreground text-sm">+1 (555) 123-4567</p>
                    <p className="text-xs text-muted-foreground">Mon-Fri, 9AM-6PM EST</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Office Hours */}
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
              <CardHeader>
                <CardTitle className="text-lg flex items-center">
                  <Clock className="w-4 h-4 mr-2" />
                  Support Hours
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium">Monday - Friday</span>
                  <span className="text-sm text-muted-foreground">9:00 AM - 6:00 PM EST</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium">Saturday</span>
                  <span className="text-sm text-muted-foreground">10:00 AM - 4:00 PM EST</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium">Sunday</span>
                  <span className="text-sm text-muted-foreground">Closed</span>
                </div>
                <div className="pt-2 border-t">
                  <p className="text-xs text-muted-foreground">
                    Emergency support available 24/7 for enterprise customers
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Location */}
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
              <CardHeader>
                <CardTitle className="text-lg flex items-center">
                  <MapPin className="w-4 h-4 mr-2" />
                  Our Location
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="font-medium text-sm">NexaBot Headquarters</p>
                  <p className="text-muted-foreground text-sm">
                    123 Innovation Drive<br />
                    Suite 400<br />
                    San Francisco, CA 94105<br />
                    United States
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* FAQ Link */}
            <Card className="bg-gradient-to-r from-primary/10 to-violet-600/10 border-primary/20 animate-fade-in-up" style={{ animationDelay: '0.4s' }}>
              <CardContent className="p-6 text-center">
                <h3 className="font-semibold mb-2">Need Quick Answers?</h3>
                <p className="text-muted-foreground text-sm mb-4">
                  Check our FAQ section for instant answers to common questions.
                </p>
                <Button variant="outline" className="w-full hover:bg-primary hover:text-white">
                  View FAQ
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* CTA Section */}
        <div className="text-center mt-12 sm:mt-16 animate-fade-in-up">
          <Card className="bg-gradient-to-r from-primary to-violet-600 text-white">
            <CardContent className="p-6 sm:p-8 lg:p-12">
              <h2 className="text-2xl sm:text-3xl font-bold mb-4">Ready to Get Started?</h2>
              <p className="text-white/90 text-base sm:text-lg mb-6 max-w-2xl mx-auto">
                Don't wait for customers to contact you. Start providing instant support today with NexaBot.
              </p>
              <Button 
                onClick={() => navigate('/signup')}
                variant="secondary"
                className="h-12 px-8 bg-white text-primary hover:bg-white/90 font-semibold shadow-glow transition-smooth text-base sm:text-lg"
              >
                Start Your Free Beta Trial
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Contact;
