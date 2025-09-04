// src/components/ErrorOverlay.tsx
import { useEffect, useState } from "react";

export default function ErrorOverlay() {
  const [errorInfo, setErrorInfo] = useState<string | null>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const handleError = (ev: any) => {
      try {
        const msg = ev?.reason?.stack || ev?.error?.stack || ev?.message || String(ev);
        setErrorInfo(String(msg || 'Unknown error'));
      } catch {
        setErrorInfo('Unknown error');
      }
      setVisible(true);
    };

    window.addEventListener('error', handleError as any);
    window.addEventListener('unhandledrejection', handleError as any);

    return () => {
      window.removeEventListener('error', handleError as any);
      window.removeEventListener('unhandledrejection', handleError as any);
    };
  }, []);

  if (!visible) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setVisible(false)} />

      <div className="relative z-10 max-w-2xl w-full mx-auto">
        <div className="bg-background border border-border rounded-2xl shadow-xl p-6">
          <div className="flex items-start gap-4">
            <div className="flex-shrink-0">
              <div className="h-12 w-12 rounded-xl flex items-center justify-center" style={{ background: 'linear-gradient(90deg,var(--primary),var(--sidebar-primary))' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden>
                  <path d="M12 2L2 7l10 5 10-5-10-5z" fill="white" />
                </svg>
              </div>
            </div>

            <div className="flex-1">
              <h2 className="text-lg font-semibold text-foreground">Something went wrong</h2>
              <p className="text-sm text-muted-foreground mt-1">An unexpected error occurred. Try reloading the page or reporting the issue.</p>

              <div className="mt-4 flex items-center gap-3">
                <button
                  onClick={() => window.location.reload()}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium text-white"
                  style={{ background: 'var(--primary)' }}
                >
                  Reload
                </button>

                <button
                  onClick={() => {
                    try {
                      const body = encodeURIComponent(`Error details:\n\n${errorInfo || 'No details'}`);
                      window.open(`mailto:hello@nexabot.ai?subject=Error Report&body=${body}`);
                    } catch {}
                  }}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium border"
                >
                  Report
                </button>

                <button
                  onClick={() => setVisible(false)}
                  className="ml-auto text-sm text-muted-foreground underline"
                >
                  Dismiss
                </button>
              </div>

              {process.env.NODE_ENV !== 'production' && errorInfo ? (
                <pre className="mt-4 max-h-40 overflow-auto text-xs bg-muted/10 p-3 rounded">{errorInfo}</pre>
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
