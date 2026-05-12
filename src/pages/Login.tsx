import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowLeft, Eye, EyeOff, Mail, Lock } from 'lucide-react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/use-toast';
import { LogoIcon, LogoText } from '@/components/ui/logo';

const Login = () => {
  const navigate = useNavigate();
  const { signIn } = useAuth();
  const { toast } = useToast();

  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const validateForm = () => {
    if (!formData.email || !formData.password) {
      toast({
        title: 'Error',
        description: 'Email and password are required',
        variant: 'destructive'
      });
      return false;
    }

    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;

    setLoading(true);
    try {
      const { error } = await signIn(formData.email, formData.password);
      if (error) {
        toast({
          title: 'Login Failed',
          description: error.message,
          variant: 'destructive'
        });
      } else {
        toast({ title: 'Welcome back!', description: 'Successfully logged in' });
        navigate('/dashboard');
      }
    } catch {
      toast({ title: 'Error', description: 'An unexpected error occurred', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Button 
                variant="ghost" 
                onClick={() => navigate('/')} 
                className="text-muted-foreground hover:text-foreground"
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to Home
              </Button>
            </div>

            <Link to="/" className="flex items-center space-x-3">
              <LogoIcon className="w-8 h-8" />
              <LogoText className="text-lg sm:text-xl" />
            </Link>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8 sm:py-12 max-w-md">
        <Card className="shadow-xl border-border/40 bg-white">
          <CardHeader className="text-center pb-6">
            <CardTitle className="text-2xl sm:text-3xl font-bold">Welcome Back</CardTitle>
            <CardDescription className="text-base">
              Sign in to access your NexaBot dashboard
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                  <Input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    placeholder="Enter your email"
                    className="pl-10 h-12"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                  <Input
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    placeholder="Enter your password"
                    className="pl-10 pr-10 h-12"
                    required
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-2 top-1/2 transform -translate-y-1/2 h-8 w-8 p-0"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </Button>
                </div>
              </div>

              <Button
                type="submit"
                className="w-full h-12 bg-primary hover:bg-primary/90 text-white font-semibold transition-smooth"
                disabled={loading}
              >
                {loading ? 'Processing...' : 'Sign In'}
              </Button>
            </form>

            <div className="text-center pt-4 border-t">
              <p className="text-sm text-muted-foreground">Don't have an account?</p>
              <Button
                type="button"
                variant="link"
                onClick={() => navigate('/signup')}
                className="text-primary font-semibold"
              >
                Sign up here
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Login;
