import { createClient } from '@supabase/supabase-js';
import type { Database } from './types';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const SUPABASE_PUBLISHABLE_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;
const IS_DEV = import.meta.env.DEV;

let _supabase: any;

if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY) {
  if (IS_DEV) {
    // Dev-friendly stub: avoid crashing, and provide a simple local auth simulation for development.
    console.warn('[supabase] VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY is not set. Using local dev supabase stub.');

    const subscribers: Array<(event: string, session: any) => void> = [];
    const SESSION_KEY = 'dev_supabase_session';

    function getStoredSession() {
      try {
        const raw = localStorage.getItem(SESSION_KEY);
        return raw ? JSON.parse(raw) : null;
      } catch { return null; }
    }
    function setStoredSession(session: any) {
      try { localStorage.setItem(SESSION_KEY, JSON.stringify(session)); } catch {}
    }
    function clearStoredSession() {
      try { localStorage.removeItem(SESSION_KEY); } catch {}
    }

    const supabaseStub: any = {
      from: () => ({
        select: async () => ({ data: null, error: new Error('Supabase client not configured (stub)') }),
        insert: async () => ({ data: null, error: new Error('Supabase client not configured (stub)') }),
        update: async () => ({ data: null, error: new Error('Supabase client not configured (stub)') }),
        delete: async () => ({ data: null, error: new Error('Supabase client not configured (stub)') }),
        upsert: async () => ({ data: null, error: new Error('Supabase client not configured (stub)') }),
        eq: () => ({ select: async () => ({ data: null, error: new Error('Supabase client not configured (stub)') }) }),
      }),
      rpc: async () => ({ data: null, error: new Error('Supabase client not configured (stub)') }),
      auth: {
        signIn: async () => ({ error: new Error('Supabase client not configured (stub)') }),
        signInWithPassword: async ({ email, password }: { email: string; password: string }) => {
          // Very simple dev auth: accept any non-empty email/password and create a session
          if (!email || !password) return { error: new Error('Email and password required') };
          const user = { id: `dev_${btoa(email).slice(0, 10)}`, email, user_metadata: {} };
          const session = { access_token: 'dev-token', user };
          setStoredSession(session);
          subscribers.forEach((s) => s('SIGNED_IN', session));
          return { data: { user, session }, error: null };
        },
        signUp: async ({ email, password, options }: any) => {
          if (!email || !password) return { error: new Error('Email and password required') };
          const user = { id: `dev_${btoa(email).slice(0, 10)}`, email, user_metadata: options?.data || {} };
          const session = { access_token: 'dev-token', user };
          setStoredSession(session);
          subscribers.forEach((s) => s('SIGNED_IN', session));
          return { data: { user, session }, error: null };
        },
        signOut: async () => {
          const session = getStoredSession();
          clearStoredSession();
          subscribers.forEach((s) => s('SIGNED_OUT', null));
          return { error: null };
        },
        getUser: async () => {
          const s = getStoredSession();
          return { data: s ? { user: s.user } : null, error: null };
        },
        getSession: async () => {
          const s = getStoredSession();
          return { data: { session: s }, error: null };
        },
        onAuthStateChange: (cb: (event: string, session: any) => void) => {
          subscribers.push(cb);
          const s = getStoredSession();
          setTimeout(() => cb(s ? 'SIGNED_IN' : 'SIGNED_OUT', s), 0);
          return { data: { subscription: { unsubscribe: () => {
            const idx = subscribers.indexOf(cb);
            if (idx >= 0) subscribers.splice(idx, 1);
          } } } };
        },
      },
      storage: {
        from: () => ({
          upload: async () => ({ data: null, error: new Error('Supabase storage not configured (stub)') }),
          download: async () => ({ data: null, error: new Error('Supabase storage not configured (stub)') }),
          remove: async () => ({ data: null, error: new Error('Supabase storage not configured (stub)') }),
        }),
      },
    };

    _supabase = supabaseStub;
  } else {
    // Production: missing keys is critical — provide a failing client to avoid accidental auth bypass.
    console.error('[supabase] VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY is missing in production. Authentication disabled.');

    const failingStub: any = {
      from: () => ({
        select: async () => ({ data: null, error: new Error('Supabase client not configured') }),
        insert: async () => ({ data: null, error: new Error('Supabase client not configured') }),
        update: async () => ({ data: null, error: new Error('Supabase client not configured') }),
        delete: async () => ({ data: null, error: new Error('Supabase client not configured') }),
        upsert: async () => ({ data: null, error: new Error('Supabase client not configured') }),
        eq: () => ({ select: async () => ({ data: null, error: new Error('Supabase client not configured') }) }),
      }),
      rpc: async () => ({ data: null, error: new Error('Supabase client not configured') }),
      auth: {
        signIn: async () => ({ error: new Error('Supabase client not configured in production') }),
        signInWithPassword: async () => ({ error: new Error('Supabase client not configured in production') }),
        signUp: async () => ({ error: new Error('Supabase client not configured in production') }),
        signOut: async () => ({ error: new Error('Supabase client not configured in production') }),
        getUser: async () => ({ data: null, error: new Error('Supabase client not configured in production') }),
        getSession: async () => ({ data: { session: null }, error: new Error('Supabase client not configured in production') }),
        onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => {} } } }),
      },
      storage: {
        from: () => ({
          upload: async () => ({ data: null, error: new Error('Supabase storage not configured') }),
          download: async () => ({ data: null, error: new Error('Supabase storage not configured') }),
          remove: async () => ({ data: null, error: new Error('Supabase storage not configured') }),
        }),
      },
    };

    _supabase = failingStub;
  }
} else {
  _supabase = createClient<Database>(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
    auth: {
      storage: localStorage,
      persistSession: true,
      autoRefreshToken: true,
    }
  });
}

export const supabase = _supabase as unknown as ReturnType<typeof createClient<Database>>;
