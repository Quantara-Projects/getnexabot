import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowLeft, Sparkles } from 'lucide-react';

const Signup = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    businessName: '',
    password: ''
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Simulate account creation
    setTimeout(() => {
      navigate('/dashboard');
    }, 500);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/20 to-background flex items-center justify-center p-4">
      {/* Background Elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 rounded-full bg-gradient-to-r from-primary/20 to-violet-500/20 blur-3xl"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 rounded-full bg-gradient-to-r from-blue-500/20 to-primary/20 blur-3xl"></div>
      </div>

      <div className="relative w-full max-w-md">
        {/* Back Button */}
        <Button 
          variant="ghost" 
          className="mb-6 text-muted-foreground hover:text-foreground"
          onClick={() => navigate('/')}
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Home
        </Button>

        <Card className="animate-fade-in-up shadow-xl">
          <CardHeader className="text-center pb-2">
            <div className="flex items-center justify-center mb-4">
              <div className="bg-gradient-to-r from-primary to-violet-600 p-3 rounded-2xl shadow-glow">
                <Sparkles className="w-8 h-8 text-white" />
              </div>
            </div>
            <CardTitle className="text-2xl font-bold">Join NexaBot Beta</CardTitle>
            <p className="text-muted-foreground">Get instant AI chatbots for your business</p>
          </CardHeader>
          
          <CardContent className="space-y-4">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Full Name</Label>
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
                  <Label htmlFor="businessName">Business Name</Label>
                  <Input
                    id="businessName"
                    name="businessName"
                    type="text"
                    placeholder="Acme Corp"
                    value={formData.businessName}
                    onChange={handleChange}
                    required
                    className="transition-smooth focus:shadow-glow"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="email">Email Address</Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  placeholder="john@acme.com"
                  value={formData.email}
                  onChange={handleChange}
                  required
                  className="transition-smooth focus:shadow-glow"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  placeholder="••••••••"
                  value={formData.password}
                  onChange={handleChange}
                  required
                  className="transition-smooth focus:shadow-glow"
                />
              </div>

              <Button 
                type="submit"
                className="w-full h-12 bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white font-semibold shadow-glow transition-smooth"
              >
                Create Free Account – Beta
              </Button>

              <div className="text-center text-sm text-muted-foreground">
                By signing up, you agree to our{' '}
                <a href="#" className="text-primary hover:underline">Terms</a> and{' '}
                <a href="#" className="text-primary hover:underline">Privacy Policy</a>
              </div>
            </form>
          </CardContent>
        </Card>

        <div className="mt-6 text-center">
          <p className="text-sm text-muted-foreground">
            Already have an account?{' '}
            <a href="#" className="text-primary hover:underline font-medium">
              Sign in
            </a>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Signup;