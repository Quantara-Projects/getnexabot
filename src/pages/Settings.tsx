import { useEffect, useState } from 'react';
import { ArrowLeft, Bot, Palette, Globe, Upload, Trash2, Save, Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { useNavigate } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';

const Settings = () => {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [settings, setSettings] = useState({
    // Account Settings
    name: 'John Doe',
    email: 'john@acme.com',
    businessName: 'Acme Corp',
    password: '',
    
    // Website Customization
    primaryColor: '#6366f1',
    secondaryColor: '#8b5cf6',
    chatBubbleStyle: 'rounded',
    fontSize: 'medium',
    
    // Bot Configuration
    botName: 'NexaBot Assistant',
    welcomeMessage: 'Hi! How can I help you today?',
    fallbackMessage: 'I\'m not sure about that. Let me connect you with a human agent.',
    websiteUrl: 'https://your-website.com',
    
    // Uploaded Files
    uploadedFiles: [
      { id: 1, name: 'FAQ_Document.pdf', size: '2.5 MB', uploaded: '2025-03-15' },
      { id: 2, name: 'Product_Catalog.docx', size: '1.8 MB', uploaded: '2025-03-14' },
      { id: 3, name: 'Support_Guidelines.txt', size: '0.5 MB', uploaded: '2025-03-13' }
    ]
  });

  const handleInputChange = (field: string, value: string) => {
    setSettings(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleDeleteFile = (fileId: number) => {
    setSettings(prev => ({
      ...prev,
      uploadedFiles: prev.uploadedFiles.filter(file => file.id !== fileId)
    }));
  };

  useEffect(() => {
    try {
      const saved = localStorage.getItem('app_settings');
      if (saved) setSettings((prev) => ({ ...prev, ...JSON.parse(saved) }));
    } catch {}
  }, []);

  const hexToHsl = (hex: string) => {
    const r = parseInt(hex.slice(1,3), 16) / 255;
    const g = parseInt(hex.slice(3,5), 16) / 255;
    const b = parseInt(hex.slice(5,7), 16) / 255;
    const max = Math.max(r,g,b), min = Math.min(r,g,b);
    let h = 0, s = 0, l = (max + min) / 2;
    if (max !== min) {
      const d = max - min;
      s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
      switch (max) {
        case r: h = (g - b) / d + (g < b ? 6 : 0); break;
        case g: h = (b - r) / d + 2; break;
        case b: h = (r - g) / d + 4; break;
      }
      h /= 6;
    }
    return `${Math.round(h*360)} ${Math.round(s*100)}% ${Math.round(l*100)}%`;
  };

  const applyTheme = (primaryHex: string, secondaryHex: string) => {
    const root = document.documentElement;
    root.style.setProperty('--primary', hexToHsl(primaryHex));
    root.style.setProperty('--secondary', hexToHsl(secondaryHex));
  };

  const handleSave = () => {
    try {
      localStorage.setItem('app_settings', JSON.stringify(settings));
      applyTheme(settings.primaryColor, settings.secondaryColor);
    } catch {}
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Button 
                variant="ghost" 
                onClick={() => navigate('/dashboard')}
                className="text-muted-foreground hover:text-foreground"
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to Dashboard
              </Button>
              <div className="flex items-center space-x-3">
                <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg">
                  <Bot className="w-5 h-5 text-white" />
                </div>
                <h1 className="text-lg sm:text-xl font-bold">Settings</h1>
              </div>
            </div>
            <Button 
              onClick={handleSave}
              className="bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white"
            >
              <Save className="w-4 h-4 mr-2" />
              Save Changes
            </Button>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 sm:px-6 py-8">
        <Tabs defaultValue="account" className="w-full">
          <TabsList className="grid w-full grid-cols-2 lg:grid-cols-4 mb-8">
            <TabsTrigger value="account">Account</TabsTrigger>
            <TabsTrigger value="appearance">Appearance</TabsTrigger>
            <TabsTrigger value="bot-config">Bot Config</TabsTrigger>
            <TabsTrigger value="data">Data & Files</TabsTrigger>
          </TabsList>

          {/* Account Settings */}
          <TabsContent value="account">
            <div className="grid lg:grid-cols-2 gap-8">
              <Card className="animate-fade-in-up">
                <CardHeader>
                  <CardTitle>Account Information</CardTitle>
                  <p className="text-muted-foreground text-sm">
                    Update your personal and business details
                  </p>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="name">Full Name</Label>
                    <Input
                      id="name"
                      value={settings.name}
                      onChange={(e) => handleInputChange('name', e.target.value)}
                      className="transition-smooth focus:shadow-glow"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="email">Email Address</Label>
                    <Input
                      id="email"
                      type="email"
                      value={settings.email}
                      onChange={(e) => handleInputChange('email', e.target.value)}
                      className="transition-smooth focus:shadow-glow"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="businessName">Business Name</Label>
                    <Input
                      id="businessName"
                      value={settings.businessName}
                      onChange={(e) => handleInputChange('businessName', e.target.value)}
                      className="transition-smooth focus:shadow-glow"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="password">New Password</Label>
                    <div className="relative">
                      <Input
                        id="password"
                        type={showPassword ? "text" : "password"}
                        value={settings.password}
                        onChange={(e) => handleInputChange('password', e.target.value)}
                        placeholder="Leave empty to keep current password"
                        className="transition-smooth focus:shadow-glow pr-10"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? (
                          <EyeOff className="h-4 w-4" />
                        ) : (
                          <Eye className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
                <CardHeader>
                  <CardTitle>Account Status</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Account Type</span>
                    <Badge variant="secondary" className="bg-green-100 text-green-700 border-green-200">
                      Beta Access
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Member Since</span>
                    <span className="text-sm text-muted-foreground">March 2025</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Chatbots Created</span>
                    <span className="text-sm font-medium">1</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Total Conversations</span>
                    <span className="text-sm font-medium">0</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Appearance Settings */}
          <TabsContent value="appearance">
            <div className="grid lg:grid-cols-2 gap-8">
              <Card className="animate-fade-in-up">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Palette className="w-5 h-5 mr-2" />
                    Website Customization
                  </CardTitle>
                  <p className="text-muted-foreground text-sm">
                    Customize the appearance of your chatbot widget
                  </p>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="primaryColor">Primary Color</Label>
                    <div className="flex space-x-3">
                      <Input
                        id="primaryColor"
                        type="color"
                        value={settings.primaryColor}
                        onChange={(e) => handleInputChange('primaryColor', e.target.value)}
                        className="w-20 h-10 p-1 transition-smooth"
                      />
                      <Input
                        value={settings.primaryColor}
                        onChange={(e) => handleInputChange('primaryColor', e.target.value)}
                        className="flex-1 transition-smooth focus:shadow-glow"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="secondaryColor">Secondary Color</Label>
                    <div className="flex space-x-3">
                      <Input
                        id="secondaryColor"
                        type="color"
                        value={settings.secondaryColor}
                        onChange={(e) => handleInputChange('secondaryColor', e.target.value)}
                        className="w-20 h-10 p-1 transition-smooth"
                      />
                      <Input
                        value={settings.secondaryColor}
                        onChange={(e) => handleInputChange('secondaryColor', e.target.value)}
                        className="flex-1 transition-smooth focus:shadow-glow"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Chat Bubble Style</Label>
                    <div className="grid grid-cols-3 gap-3">
                      {['rounded', 'square', 'pill'].map((style) => (
                        <Button
                          key={style}
                          variant={settings.chatBubbleStyle === style ? "default" : "outline"}
                          onClick={() => handleInputChange('chatBubbleStyle', style)}
                          className="capitalize"
                        >
                          {style}
                        </Button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Font Size</Label>
                    <div className="grid grid-cols-3 gap-3">
                      {['small', 'medium', 'large'].map((size) => (
                        <Button
                          key={size}
                          variant={settings.fontSize === size ? "default" : "outline"}
                          onClick={() => handleInputChange('fontSize', size)}
                          className="capitalize"
                        >
                          {size}
                        </Button>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
                <CardHeader>
                  <CardTitle>Live Preview</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="bg-secondary/30 rounded-lg p-4 space-y-3">
                    <div className="flex justify-end">
                      <div 
                        className={`max-w-[80%] px-4 py-2 text-sm text-white ${
                          settings.chatBubbleStyle === 'rounded' ? 'rounded-2xl rounded-br-md' :
                          settings.chatBubbleStyle === 'square' ? 'rounded-none' : 'rounded-full'
                        }`}
                        style={{ backgroundColor: settings.primaryColor }}
                      >
                        Hi, do you offer 24/7 support?
                      </div>
                    </div>
                    <div className="flex justify-start">
                      <div 
                        className={`max-w-[80%] px-4 py-2 text-sm ${
                          settings.chatBubbleStyle === 'rounded' ? 'rounded-2xl rounded-bl-md' :
                          settings.chatBubbleStyle === 'square' ? 'rounded-none' : 'rounded-full'
                        }`}
                        style={{ 
                          backgroundColor: settings.secondaryColor,
                          color: 'white',
                          fontSize: settings.fontSize === 'small' ? '12px' : 
                                   settings.fontSize === 'large' ? '16px' : '14px'
                        }}
                      >
                        {settings.welcomeMessage}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Bot Configuration */}
          <TabsContent value="bot-config">
            <div className="grid lg:grid-cols-2 gap-8">
              <Card className="animate-fade-in-up">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Bot className="w-5 h-5 mr-2" />
                    Chatbot Settings
                  </CardTitle>
                  <p className="text-muted-foreground text-sm">
                    Configure your chatbot's behavior and responses
                  </p>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="botName">Chatbot Name</Label>
                    <Input
                      id="botName"
                      value={settings.botName}
                      onChange={(e) => handleInputChange('botName', e.target.value)}
                      className="transition-smooth focus:shadow-glow"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="welcomeMessage">Welcome Message</Label>
                    <Input
                      id="welcomeMessage"
                      value={settings.welcomeMessage}
                      onChange={(e) => handleInputChange('welcomeMessage', e.target.value)}
                      className="transition-smooth focus:shadow-glow"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="fallbackMessage">Fallback Message</Label>
                    <Input
                      id="fallbackMessage"
                      value={settings.fallbackMessage}
                      onChange={(e) => handleInputChange('fallbackMessage', e.target.value)}
                      className="transition-smooth focus:shadow-glow"
                    />
                    <p className="text-xs text-muted-foreground">
                      Shown when the bot can't answer a question
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Globe className="w-5 h-5 mr-2" />
                    Website Integration
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="websiteUrl">Website URL</Label>
                    <Input
                      id="websiteUrl"
                      value={settings.websiteUrl}
                      onChange={(e) => handleInputChange('websiteUrl', e.target.value)}
                      className="transition-smooth focus:shadow-glow"
                    />
                  </div>

                  <div className="bg-secondary/30 rounded-lg p-4">
                    <h4 className="font-semibold mb-2">Embed Code</h4>
                    <p className="text-sm text-muted-foreground mb-3">
                      Copy this code to your website to add the chatbot widget:
                    </p>
                    <div className="bg-background border rounded p-3 text-xs font-mono overflow-x-auto">
                      {`<script src="https://cdn.nexabot.com/widget.js"></script>
<script>
  NexaBot.init({
    botId: 'your-bot-id',
    primaryColor: '${settings.primaryColor}',
    position: 'bottom-right'
  });
</script>`}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Data & Files */}
          <TabsContent value="data">
            <div className="space-y-8">
              <Card className="animate-fade-in-up">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Upload className="w-5 h-5 mr-2" />
                    Uploaded Training Data
                  </CardTitle>
                  <p className="text-muted-foreground text-sm">
                    Manage the files used to train your chatbot. Note: Deleting files will affect bot performance.
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {settings.uploadedFiles.map((file) => (
                      <div key={file.id} className="flex items-center justify-between p-4 border rounded-lg">
                        <div className="flex items-center space-x-4">
                          <div className="bg-primary/10 p-2 rounded-lg">
                            <Upload className="w-4 h-4 text-primary" />
                          </div>
                          <div>
                            <h4 className="font-medium text-sm">{file.name}</h4>
                            <p className="text-xs text-muted-foreground">
                              {file.size} • Uploaded {file.uploaded}
                            </p>
                          </div>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleDeleteFile(file.id)}
                          className="text-red-600 hover:text-red-700 hover:bg-red-50"
                        >
                          <Trash2 className="w-4 h-4 mr-2" />
                          Delete
                        </Button>
                      </div>
                    ))}

                    {settings.uploadedFiles.length === 0 && (
                      <div className="text-center py-8 text-red-700 bg-red-50 border border-red-200 rounded">
                        <Upload className="w-8 h-8 mx-auto mb-2 opacity-50" />
                        <p>Bot training data missing. Your bot will not work until you upload files or provide a website URL.</p>
                      </div>
                    )}
                  </div>

                  <div className="mt-6 pt-6 border-t">
                    <Button className="w-full bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white">
                      <Upload className="w-4 h-4 mr-2" />
                      Upload New Training Data
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card className="animate-fade-in-up border-red-200 bg-red-50/50" style={{ animationDelay: '0.1s' }}>
                <CardHeader>
                  <CardTitle className="text-red-800">Danger Zone</CardTitle>
                  <p className="text-red-600 text-sm">
                    These actions cannot be undone. Please proceed with caution.
                  </p>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between p-4 border border-red-200 rounded-lg">
                    <div>
                      <h4 className="font-medium text-red-800">Delete All Training Data</h4>
                      <p className="text-sm text-red-600">
                        This will remove all uploaded files and reset your chatbot
                      </p>
                    </div>
                    <Button variant="outline" className="text-red-600 border-red-200 hover:bg-red-50">
                      Delete All Data
                    </Button>
                  </div>

                  <div className="flex items-center justify-between p-4 border border-red-200 rounded-lg">
                    <div>
                      <h4 className="font-medium text-red-800">Delete Account</h4>
                      <p className="text-sm text-red-600">
                        Permanently delete your account and all associated data
                      </p>
                    </div>
                    <Button variant="outline" className="text-red-600 border-red-200 hover:bg-red-50">
                      Delete Account
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Settings;
