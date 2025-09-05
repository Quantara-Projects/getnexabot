import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Bot, ArrowLeft, Eye, EyeOff, Mail, Lock, User, Building } from 'lucide-react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/use-toast';
import CustomCaptcha from '@/components/CustomCaptcha';
import { getServerApiPath } from '@/lib/api';

const Signup = () => {
  const navigate = useNavigate();
  const { signUp, signIn } = useAuth();
  const { toast } = useToast();
  
  const [isLogin, setIsLogin] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [captchaVerified, setCaptchaVerified] = useState(false);
  const [captchaReset, setCaptchaReset] = useState(0);
  const [loading, setLoading] = useState(false);
  
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    fullName: '',
    businessName: ''
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
        title: "Error",
        description: "Email and password are required",
        variant: "destructive"
      });
      return false;
    }

    if (!isLogin && formData.password !== formData.confirmPassword) {
      toast({
        title: "Error",
        description: "Passwords do not match",
        variant: "destructive"
      });
      return false;
    }

    if (!isLogin && formData.password.length < 6) {
      toast({
        title: "Error",
        description: "Password must be at least 6 characters long",
        variant: "destructive"
      });
      return false;
    }

    if (!captchaVerified) {
      toast({
        title: "Error",
        description: "Please complete the security verification",
        variant: "destructive"
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
      if (isLogin) {
        const { error } = await signIn(formData.email, formData.password);
        
        if (error) {
          toast({
            title: "Login Failed",
            description: error.message,
            variant: "destructive"
          });
          setCaptchaReset(prev => prev + 1);
          setCaptchaVerified(false);
        } else {
          toast({
            title: "Welcome back!",
            description: "Successfully logged in"
          });
          navigate('/dashboard');
        }
      } else {
        const { error } = await signUp(formData.email, formData.password, {
          full_name: formData.fullName,
          business_name: formData.businessName
        });
        
        if (error) {
          toast({
            title: "Signup Failed",
            description: error.message,
            variant: "destructive"
          });
          setCaptchaReset(prev => prev + 1);
          setCaptchaVerified(false);
        } else {
          try {
            const { supabase } = await import('@/integrations/supabase/client');
            const { data } = await supabase.auth.getSession();
            const token = data.session?.access_token;
            if (token) {
              const apiPath = getServerApiPath('/send-verify');
              await fetch(apiPath, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({ email: formData.email }),
              });
            }
          } catch {}
          toast({ title: 'Account Created!', description: 'Verification email sent.' });
          navigate(`/verify?email=${encodeURIComponent(formData.email)}`);
        }
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "An unexpected error occurred",
        variant: "destructive"
      });
      setCaptchaReset(prev => prev + 1);
      setCaptchaVerified(false);
    } finally {
      setLoading(false);
    }
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
                onClick={() => navigate('/')}
                className="text-muted-foreground hover:text-foreground"
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to Home
              </Button>
            </div>
            
            <Link to="/" className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg">
                <Bot className="w-5 h-5 text-white" />
              </div>
              <span className="text-lg sm:text-xl font-bold">NexaBot</span>
            </Link>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8 sm:py-12 max-w-md">
        <Card className="shadow-2xl border-0 bg-white/90 backdrop-blur-sm">
          <CardHeader className="text-center pb-6">
            <CardTitle className="text-2xl sm:text-3xl font-bold">
              {isLogin ? 'Welcome Back' : 'Create Account'}
            </CardTitle>
            <CardDescription className="text-base">
              {isLogin 
                ? 'Sign in to access your NexaBot dashboard'
                : 'Start your free beta trial today'
              }
            </CardDescription>
          </CardHeader>
          
          <CardContent className="space-y-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Email Field */}
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

              {/* Sign up specific fields */}
              {!isLogin && (
                <>
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-foreground">Full Name</label>
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                      <Input
                        type="text"
                        name="fullName"
                        value={formData.fullName}
                        onChange={handleInputChange}
                        placeholder="Enter your full name"
                        className="pl-10 h-12"
                        required
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium text-foreground">Business Name</label>
                    <div className="relative">
                      <Building className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                      <Input
                        type="text"
                        name="businessName"
                        value={formData.businessName}
                        onChange={handleInputChange}
                        placeholder="Enter your business name"
                        className="pl-10 h-12"
                      />
                    </div>
                  </div>
                </>
              )}

              {/* Password Field */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                  <Input
                    type={showPassword ? "text" : "password"}
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

              {/* Confirm Password for signup */}
              {!isLogin && (
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground">Confirm Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                    <Input
                      type={showPassword ? "text" : "password"}
                      name="confirmPassword"
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      placeholder="Confirm your password"
                      className="pl-10 h-12"
                      required
                    />
                  </div>
                </div>
              )}

              {/* Custom Captcha */}
              <CustomCaptcha 
                onVerify={setCaptchaVerified}
                resetTrigger={captchaReset}
              />

              {/* Submit Button */}
              <Button
                type="submit"
                className="w-full h-12 bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white font-semibold shadow-glow transition-smooth"
                disabled={loading || !captchaVerified}
              >
                {loading ? 'Processing...' : (isLogin ? 'Sign In' : 'Create Account')}
              </Button>
            </form>

            {/* Toggle between login/signup */}
            <div className="text-center pt-4 border-t">
              <p className="text-sm text-muted-foreground">
                {isLogin ? "Don't have an account?" : "Already have an account?"}
              </p>
              <Button
                type="button"
                variant="link"
                onClick={() => {
                  setIsLogin(!isLogin);
                  setCaptchaVerified(false);
                  setCaptchaReset(prev => prev + 1);
                  setFormData({
                    email: '',
                    password: '',
                    confirmPassword: '',
                    fullName: '',
                    businessName: ''
                  });
                }}
                className="text-primary font-semibold"
              >
                {isLogin ? 'Sign up here' : 'Sign in here'}
              </Button>
            </div>

            {!isLogin && (
              <div className="text-xs text-muted-foreground text-center leading-relaxed">
                By creating an account, you agree to our{' '}
                <Link to="/terms" className="text-primary hover:underline">Terms of Service</Link>
                {' '}and{' '}
                <Link to="/privacy" className="text-primary hover:underline">Privacy Policy</Link>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Signup;
