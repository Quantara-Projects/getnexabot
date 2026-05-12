import { Button } from "@/components/ui/button";
import { ArrowRight, Sparkles } from "lucide-react";
import { useNavigate } from "react-router-dom";
import Navigation from "./Navigation";
import { LogoIcon } from "@/components/ui/logo";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

const Hero = () => {
  const navigate = useNavigate();
  const [activeUserCount, setActiveUserCount] = useState(500);

  useEffect(() => {
    const fetchUserCount = async () => {
      try {
        const { count } = await supabase
          .from("profiles")
          .select("*", { count: "exact", head: true });
        if (count !== null) setActiveUserCount(Math.max(500, count));
      } catch {}
    };
    fetchUserCount();

    // Live updates when new users sign up (keeps landing stats current)
    const realtime = typeof (supabase as any).channel === "function"
      ? (supabase as any)
          .channel("profiles-count")
          .on(
            "postgres_changes",
            { event: "*", schema: "public", table: "profiles" },
            () => fetchUserCount()
          )
          .subscribe()
      : null;

    return () => {
      if (realtime && typeof (supabase as any).removeChannel === "function") {
        (supabase as any).removeChannel(realtime);
      }
    };
  }, []);

  const stats = [
    { label: "Response Time", value: "5s" },
    { label: "Active Users", value: activeUserCount.toLocaleString() },
    { label: "Uptime", value: "99.9%" },
  ];

  return (
    <>
      <Navigation />
      <section className="relative min-h-screen flex items-center bg-background overflow-hidden">
        {/* Background gradient mesh */}
        <div className="absolute inset-0">
          <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-gradient-radial from-primary/5 to-transparent rounded-full blur-3xl" />
          <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-gradient-radial from-cyan-400/5 to-transparent rounded-full blur-3xl" />
          <div className="absolute top-1/3 right-0 w-[300px] h-[300px] bg-gradient-radial from-primary/8 to-transparent rounded-full blur-2xl" />
          <div
            className="absolute inset-0 opacity-[0.015]"
            style={{
              backgroundImage: `linear-gradient(hsl(175 72% 50%) 1px, transparent 1px), linear-gradient(90deg, hsl(175 72% 50%) 1px, transparent 1px)`,
              backgroundSize: "64px 64px",
            }}
          />
        </div>

        <div className="container mx-auto px-6 relative z-10 pt-24 pb-20">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            {/* Left Content */}
            <div className="animate-fade-up space-y-8">
              {/* Badge */}
              <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/8 border border-primary/15 text-primary text-sm font-medium">
                <Sparkles className="w-4 h-4" />
                <span>AI-Powered Customer Support Platform</span>
              </div>

              <div className="space-y-4">
                <h1 className="text-5xl lg:text-6xl xl:text-7xl font-bold leading-[1.08] tracking-tight text-foreground">
                  AI Chatbots That
                  <span className="gradient-text block mt-1">
                    Reply Instantly
                  </span>
                </h1>

                <p className="text-lg lg:text-xl text-neutral-500 leading-relaxed max-w-lg">
                  Deploy intelligent AI assistants across your website,
                  WhatsApp, and Messenger. Get 24/7 support, capture leads, and
                  automate responses without a technical team.
                </p>
              </div>

              <div className="flex flex-col sm:flex-row gap-4">
                <Button
                  size="lg"
                  className="h-14 px-10 bg-primary text-white hover:bg-primary/90 shadow-md hover:shadow-lg active:scale-[0.98] transition-all text-base font-semibold rounded-lg"
                  onClick={() => navigate("/signup")}
                >
                  Start Free Beta
                  <ArrowRight className="w-5 h-5 ml-2" />
                </Button>
              </div>

              {/* Trust indicators */}
              <div className="flex items-center gap-3 text-sm text-neutral-400">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-success-500 animate-pulse" />
                  <span>Free during beta</span>
                </div>
                <span className="text-neutral-300">|</span>
                <span>No credit card required</span>
                <span className="text-neutral-300">|</span>
                <span>Setup in 5 minutes</span>
              </div>

              {/* Stats strip - bigger */}
              <div className="flex items-center gap-10 pt-5 border-t border-border/40">
                {stats.map((stat) => (
                  <div key={stat.label} className="space-y-1">
                    <div className="text-3xl font-bold text-foreground">
                      {stat.value}
                    </div>
                    <div className="text-sm text-neutral-400">{stat.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right Content - Natural Chat Preview */}
            <div
              className="relative animate-fade-up"
              style={{ animationDelay: "0.15s" }}
            >
              <div className="relative bg-white rounded-2xl border border-border/40 shadow-xl p-5 max-w-md mx-auto">
                {/* Chat Header */}
                <div className="flex items-center justify-between pb-3 border-b border-border/30 mb-3">
                  <div className="flex items-center gap-3">
                    <LogoIcon className="w-9 h-9" />
                    <div>
                      <div className="text-sm font-semibold text-foreground">
                        NexaBot
                      </div>
                      <div className="flex items-center gap-1.5">
                        <div className="w-1.5 h-1.5 rounded-full bg-success-500" />
                        <span className="text-xs text-neutral-400">
                          Online - Instant replies
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Chat Messages - No typing delay, shows instantly */}
                <div className="space-y-3.5 min-h-[260px]">
                  {/* User message */}
                  <div className="flex justify-end">
                    <div className="bg-primary text-white rounded-2xl rounded-br-sm px-4 py-2.5 max-w-[80%] text-sm leading-relaxed shadow-sm">
                      Hi, do you offer 24/7 support?
                    </div>
                  </div>

                  {/* Bot response - shown immediately without typing delay */}
                  <div className="flex justify-start">
                    <div className="bg-secondary rounded-2xl rounded-bl-sm px-4 py-2.5 max-w-[85%] text-sm leading-relaxed border border-border/20">
                      Absolutely! I am available 24/7 to assist your customers
                      instantly. What kind of business do you run?
                    </div>
                  </div>
                </div>

                {/* Chat Input */}
                <div className="pt-3 border-t border-border/30 mt-3">
                  <div className="flex items-center gap-2 bg-secondary/60 rounded-xl px-4 py-2.5">
                    <span className="text-sm text-neutral-400 flex-1">
                      Ask me anything...
                    </span>
                    <div className="w-7 h-7 rounded-lg gradient-bg flex items-center justify-center">
                      <ArrowRight className="w-3.5 h-3.5 text-white" />
                    </div>
                  </div>
                </div>

                {/* Floating status badges */}
                <div className="absolute -top-3 -right-3 bg-white border border-border/50 rounded-lg px-3 py-1.5 shadow-md">
                  <div className="flex items-center gap-1.5 text-xs font-medium text-success-700">
                    <div className="w-1.5 h-1.5 rounded-full bg-success-500" />
                    Instant Reply
                  </div>
                </div>
                <div className="absolute -bottom-3 -left-3 bg-white border border-border/50 rounded-lg px-3 py-1.5 shadow-md">
                  <div className="flex items-center gap-1.5 text-xs font-medium text-primary">
                    <svg
                      viewBox="0 0 16 16"
                      className="w-3.5 h-3.5 fill-primary"
                    >
                      <path d="M8 1C4.136 1 1 4.136 1 8s3.136 7 7 7 7-3.136 7-7-3.136-7-7-7zm0 12.5A5.5 5.5 0 118 2.5a5.5 5.5 0 010 11zM7.5 4h1v4.5H7.5V4zm0 5.5h1v1h-1v-1z" />
                    </svg>
                    Lead Captured
                  </div>
                </div>
              </div>

              {/* Decorative elements */}
              <div className="absolute -z-10 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-[120%] bg-gradient-radial from-primary/3 to-transparent rounded-full blur-2xl" />
            </div>
          </div>
        </div>
      </section>
    </>
  );
};

export default Hero;
