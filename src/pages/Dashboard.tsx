import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Bot, 
  MessageSquare, 
  Users, 
  Zap, 
  Settings, 
  Upload, 
  Link, 
  Smartphone, 
  Globe,
  BarChart3,
  CheckCircle,
  Clock
} from 'lucide-react';

const Dashboard = () => {
  const [setupStep, setSetupStep] = useState(1);
  const [businessName] = useState("Acme Corp"); // Would come from auth context

  const handleNextStep = () => {
    if (setupStep < 3) {
      setSetupStep(setupStep + 1);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg">
                <Bot className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold">NexaBot</h1>
                <p className="text-sm text-muted-foreground">Welcome back, {businessName}</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant="secondary" className="bg-green-100 text-green-700 border-green-200">
                Beta Access
              </Badge>
              <Button variant="outline" size="sm">
                <Settings className="w-4 h-4 mr-2" />
                Settings
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        {/* Welcome Banner */}
        <Card className="mb-8 bg-gradient-to-r from-primary/10 to-violet-600/10 border-primary/20 animate-fade-in-up">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold mb-2">Welcome, {businessName}! 🎉</h2>
                <p className="text-muted-foreground">Your NexaBot is ready to be configured. Let's get you set up in 3 simple steps.</p>
              </div>
              <div className="hidden md:block">
                <div className="bg-gradient-to-r from-primary to-violet-600 p-4 rounded-2xl animate-float">
                  <Bot className="w-12 h-12 text-white" />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Setup Wizard */}
          <div className="lg:col-span-2">
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Zap className="w-5 h-5 mr-2 text-primary" />
                  Setup Wizard
                </CardTitle>
                <Progress value={(setupStep / 3) * 100} className="w-full" />
                <p className="text-sm text-muted-foreground">Step {setupStep} of 3</p>
              </CardHeader>
              <CardContent>
                <Tabs value={`step-${setupStep}`} className="w-full">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="step-1" className="flex items-center space-x-2">
                      <Upload className="w-4 h-4" />
                      <span className="hidden sm:inline">Train Bot</span>
                    </TabsTrigger>
                    <TabsTrigger value="step-2" className="flex items-center space-x-2">
                      <Link className="w-4 h-4" />
                      <span className="hidden sm:inline">Connect</span>
                    </TabsTrigger>
                    <TabsTrigger value="step-3" className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4" />
                      <span className="hidden sm:inline">Launch</span>
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="step-1" className="space-y-4 mt-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Upload Your Business Data</h3>
                      <p className="text-muted-foreground mb-4">Help NexaBot understand your business by providing FAQs, website content, or documents.</p>
                    </div>
                    
                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="website-url">Website URL (Recommended)</Label>
                        <Input 
                          id="website-url"
                          placeholder="https://your-website.com" 
                          className="mt-2"
                        />
                        <p className="text-xs text-muted-foreground mt-1">We'll automatically extract relevant information</p>
                      </div>
                      
                      <div className="text-center">
                        <p className="text-sm text-muted-foreground mb-4">— OR —</p>
                      </div>
                      
                      <div className="border-2 border-dashed border-border rounded-lg p-8 text-center">
                        <Upload className="w-8 h-8 text-muted-foreground mx-auto mb-4" />
                        <p className="font-medium mb-2">Upload FAQs or Documents</p>
                        <p className="text-sm text-muted-foreground mb-4">Drag & drop files or click to browse</p>
                        <Button variant="outline">
                          Browse Files
                        </Button>
                      </div>
                    </div>

                    <Button 
                      onClick={handleNextStep} 
                      className="w-full bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90"
                    >
                      Continue to Integrations
                    </Button>
                  </TabsContent>

                  <TabsContent value="step-2" className="space-y-4 mt-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Connect Your Channels</h3>
                      <p className="text-muted-foreground mb-4">Choose where you want NexaBot to provide customer support.</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card className="p-4 text-center border-2 hover:border-primary cursor-pointer transition-smooth">
                        <Globe className="w-8 h-8 text-primary mx-auto mb-2" />
                        <h4 className="font-semibold">Website Chat</h4>
                        <p className="text-xs text-muted-foreground">Embed on your site</p>
                        <Badge variant="secondary" className="mt-2">Recommended</Badge>
                      </Card>

                      <Card className="p-4 text-center border-2 hover:border-primary cursor-pointer transition-smooth">
                        <MessageSquare className="w-8 h-8 text-green-600 mx-auto mb-2" />
                        <h4 className="font-semibold">WhatsApp</h4>
                        <p className="text-xs text-muted-foreground">Business API</p>
                        <Badge variant="outline" className="mt-2">Coming Soon</Badge>
                      </Card>

                      <Card className="p-4 text-center border-2 hover:border-primary cursor-pointer transition-smooth">
                        <Smartphone className="w-8 h-8 text-blue-600 mx-auto mb-2" />
                        <h4 className="font-semibold">Messenger</h4>
                        <p className="text-xs text-muted-foreground">Facebook Pages</p>
                        <Badge variant="outline" className="mt-2">Coming Soon</Badge>
                      </Card>
                    </div>

                    <Button 
                      onClick={handleNextStep} 
                      className="w-full bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90"
                    >
                      Configure Settings
                    </Button>
                  </TabsContent>

                  <TabsContent value="step-3" className="space-y-4 mt-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Customize & Launch</h3>
                      <p className="text-muted-foreground mb-4">Personalize your chatbot's appearance and behavior.</p>
                    </div>

                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="bot-name">Chatbot Name</Label>
                        <Input 
                          id="bot-name"
                          placeholder="NexaBot Assistant" 
                          className="mt-2"
                        />
                      </div>

                      <div>
                        <Label htmlFor="greeting">Welcome Greeting</Label>
                        <Input 
                          id="greeting"
                          placeholder="Hi! How can I help you today?" 
                          className="mt-2"
                        />
                      </div>
                    </div>

                    <Button 
                      className="w-full bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white"
                    >
                      Launch NexaBot 🚀
                    </Button>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Live Preview */}
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
              <CardHeader>
                <CardTitle className="text-lg">Live Chat Preview</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-secondary/30 rounded-lg p-4 space-y-3">
                  <div className="chat-bubble max-w-[80%] ml-auto">
                    <p className="text-sm">Hi, do you offer 24/7 support?</p>
                  </div>
                  <div className="chat-bubble max-w-[80%]">
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
                <p className="text-xs text-muted-foreground mt-3 text-center">
                  Complete setup to test your bot
                </p>
              </CardContent>
            </Card>

            {/* Beta Analytics */}
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
              <CardHeader>
                <CardTitle className="flex items-center text-lg">
                  <BarChart3 className="w-5 h-5 mr-2" />
                  Analytics Preview
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Conversations</span>
                  <span className="font-bold">0</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Leads Captured</span>
                  <span className="font-bold">0</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Avg Response Time</span>
                  <span className="font-bold text-green-600">&lt; 1s</span>
                </div>
                <div className="pt-2 border-t">
                  <Badge variant="secondary" className="w-full justify-center bg-orange-100 text-orange-700">
                    <Clock className="w-3 h-3 mr-1" />
                    Beta Mode Active
                  </Badge>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;