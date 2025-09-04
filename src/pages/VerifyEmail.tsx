import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { MailCheck, Mail } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

const useQuery = () => new URLSearchParams(useLocation().search);

const VerifyEmail = () => {
  const { toast } = useToast();
  const query = useQuery();
  const navigate = useNavigate();
  const [email, setEmail] = useState(query.get('email') || '');
  const [sending, setSending] = useState(false);

  useEffect(() => { setEmail(query.get('email') || ''); }, [query]);

  const resend = async () => {
    const { data } = await supabase.auth.getSession();
    const token = data.session?.access_token;
    if (!token || !email) {
      toast({ title: 'Not authenticated', description: 'Please sign in again.', variant: 'destructive' });
      return navigate('/login');
    }
    try {
      setSending(true);
      const res = await fetch('/api/send-verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ email }),
      });
      if (!res.ok) throw new Error('Failed');
      toast({ title: 'Verification email sent', description: `Sent to ${email}` });
    } catch {
      toast({ title: 'Failed to send email', description: 'Try again later.', variant: 'destructive' });
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      <div className="container mx-auto px-4 py-12 max-w-lg">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><MailCheck className="w-5 h-5"/> Verify your email</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">We sent a confirmation link to your email. Click the link to verify your NexaBot account.</p>
            <div className="space-y-2">
              <label className="text-sm">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"/>
                <Input value={email} onChange={(e)=>setEmail(e.target.value)} className="pl-10"/>
              </div>
            </div>
            <Button onClick={resend} disabled={sending || !email} className="w-full">{sending? 'Sending…':'Resend verification email'}</Button>
            <Button variant="link" onClick={()=>navigate('/dashboard')} className="w-full">Back to Dashboard</Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default VerifyEmail;
