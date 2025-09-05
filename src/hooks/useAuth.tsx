import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  signUp: (email: string, password: string, metadata?: any) => Promise<{ error: any }>;
  signIn: (email: string, password: string) => Promise<{ error: any }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  const ensureProfileAndSettings = async (u: User) => {
    try {
      const { data: profs } = await supabase
        .from('profiles')
        .select('id')
        .eq('user_id', u.id)
        .limit(1);
      if (!profs || profs.length === 0) {
        await supabase.from('profiles').insert({
          user_id: u.id,
          full_name: u.user_metadata?.full_name || null,
          business_name: null,
          website_url: null,
        });
      }
      const { data: settings } = await supabase
        .from('user_settings')
        .select('id')
        .eq('user_id', u.id)
        .limit(1);
      if (!settings || settings.length === 0) {
        await supabase.from('user_settings').insert({ user_id: u.id });
      }
    } catch {}
  };

  useEffect(() => {
    // Auto-logout if user hasn't been active for 30 days
    const THIRTY_DAYS_MS = 1000 * 60 * 60 * 24 * 30;
    const LAST_ACTIVE_KEY = 'lastActive';

    const updateLastActive = () => {
      try { localStorage.setItem(LAST_ACTIVE_KEY, String(Date.now())); } catch {}
    };

    // Update last active on interactions
    window.addEventListener('visibilitychange', updateLastActive);
    window.addEventListener('mousemove', updateLastActive);
    window.addEventListener('keydown', updateLastActive);
    window.addEventListener('focus', updateLastActive);

    // Check on init
    try {
      const raw = localStorage.getItem(LAST_ACTIVE_KEY);
      if (raw) {
        const last = Number(raw) || 0;
        if (Date.now() - last > THIRTY_DAYS_MS) {
          // Too long, sign out and clear session
          try { supabase.auth.signOut(); } catch {}
          try { localStorage.removeItem(LAST_ACTIVE_KEY); } catch {}
        }
      }
      updateLastActive();
    } catch {}

    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      async (event, session) => {
        setSession(session);
        setUser(session?.user ?? null);
        setLoading(false);

        if (event === 'SIGNED_IN' && session?.user) {
          ensureProfileAndSettings(session.user);
          setTimeout(() => {
            supabase.rpc('log_security_event', {
              p_user_id: session.user.id,
              p_action: 'LOGIN',
              p_ip_address: null,
              p_user_agent: navigator.userAgent,
              p_success: true
            });
          }, 0);
        }
      }
    );

    supabase.auth.getSession().then(async ({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
      if (session?.user) await ensureProfileAndSettings(session.user);
    });

    return () => {
      subscription.unsubscribe();
      window.removeEventListener('visibilitychange', updateLastActive);
      window.removeEventListener('mousemove', updateLastActive);
      window.removeEventListener('keydown', updateLastActive);
      window.removeEventListener('focus', updateLastActive);
    };
  }, []);

  const signUp = async (email: string, password: string, metadata?: any) => {
    const redirectUrl = `${window.location.origin}/`;

    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: redirectUrl,
        data: metadata
      }
    });

    supabase.rpc('log_security_event', {
      p_user_id: null,
      p_action: 'SIGNUP_ATTEMPT',
      p_ip_address: null,
      p_user_agent: navigator.userAgent,
      p_success: !error,
      p_details: error ? { error: error.message } : null
    });

    return { error };
  };

  const signIn = async (email: string, password: string) => {
    // Pre-check: signal to user if this email likely exists by attempting a login
    const { error } = await supabase.auth.signInWithPassword({ email, password });

    supabase.rpc('log_security_event', {
      p_user_id: null,
      p_action: 'LOGIN_ATTEMPT',
      p_ip_address: null,
      p_user_agent: navigator.userAgent,
      p_success: !error,
      p_details: error ? { error: error.message } : null
    });

    // On successful login, profile/settings will be ensured by auth state effect
    return { error };
  };

  const signOut = async () => {
    if (user) {
      supabase.rpc('log_security_event', {
        p_user_id: user.id,
        p_action: 'LOGOUT',
        p_ip_address: null,
        p_user_agent: navigator.userAgent,
        p_success: true
      });
    }
    await supabase.auth.signOut();
  };

  return (
    <AuthContext.Provider value={{
      user,
      session,
      loading,
      signUp,
      signIn,
      signOut
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
