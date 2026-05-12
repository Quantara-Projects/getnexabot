import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowRight, Upload, Link, Rocket, CheckCircle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { LogoIcon } from "@/components/ui/logo";

const HowItWorks = () => {
  const navigate = useNavigate();

  const steps = [
    {
      step: 1,
      icon: Upload,
      title: "Sign Up & Train",
      description:
        "Create your account and upload FAQs, documents, or link your website. NexaBot learns your business instantly.",
      color: "text-primary",
      bgColor: "bg-primary/10",
    },
    {
      step: 2,
      icon: Link,
      title: "Connect Channels",
      description:
        "Integrate with your website, WhatsApp, Messenger, Slack, or Discord. One-click setup for all platforms.",
      color: "text-emerald-600",
      bgColor: "bg-emerald-500/10",
    },
    {
      step: 3,
      icon: Rocket,
      title: "Go Live",
      description:
        "Your AI chatbot starts providing instant replies 24/7. Capture leads, resolve issues, and grow your business.",
      color: "text-violet-600",
      bgColor: "bg-violet-500/10",
    },
  ];

  return (
    <section
      id="how-it-works"
      className="py-24 bg-secondary/30 relative overflow-hidden"
    >
      {/* Background decoration */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-1/3 w-px h-full bg-gradient-to-b from-transparent via-border/30 to-transparent" />
        <div className="absolute top-0 right-1/3 w-px h-full bg-gradient-to-b from-transparent via-border/30 to-transparent" />
      </div>

      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="text-center mb-16 max-w-2xl mx-auto space-y-4 animate-fade-up">
          <h2 className="text-4xl lg:text-5xl font-bold tracking-tight text-foreground">
            Get Live in
            <span className="gradient-text block">Three Simple Steps</span>
          </h2>
          <p className="text-lg text-neutral-500 leading-relaxed">
            No technical expertise required. From signup to live deployment in
            under 5 minutes.
          </p>
        </div>

        <div className="max-w-5xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-20">
            {steps.map((step, index) => (
              <div
                key={index}
                className="relative animate-fade-up"
                style={{ animationDelay: `${index * 0.12}s` }}
              >
                <Card className="h-full border-border/40 hover:border-border/70 transition-all duration-300 hover:shadow-lg group">
                  <CardContent className="p-7 text-center">
                    {/* Step Number */}
                    <div className="relative mb-5">
                      <div
                        className={`w-16 h-16 ${step.bgColor} rounded-2xl flex items-center justify-center mx-auto group-hover:scale-110 transition-transform duration-300`}
                      >
                        <step.icon className={`w-7 h-7 ${step.color}`} />
                      </div>
                      <div className="absolute -top-1.5 -right-1.5 w-7 h-7 rounded-full gradient-bg flex items-center justify-center text-white font-bold text-xs shadow-sm">
                        {step.step}
                      </div>
                    </div>

                    <h3 className="text-lg font-bold mb-3 text-foreground">
                      {step.title}
                    </h3>
                    <p className="text-sm text-neutral-500 leading-relaxed mb-5">
                      {step.description}
                    </p>

                    <div className="flex items-center justify-center gap-1.5 text-xs font-medium text-emerald-600">
                      <CheckCircle className="w-4 h-4" />
                      <span>Ready in minutes</span>
                    </div>
                  </CardContent>
                </Card>

                {/* Arrow connector */}
                {index < steps.length - 1 && (
                  <div className="hidden lg:flex absolute top-1/2 -right-4 transform -translate-y-1/2 z-10">
                    <ArrowRight className="w-6 h-6 text-primary" />
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* CTA - No Schedule Demo button */}
          <div
            className="text-center animate-fade-up"
            style={{ animationDelay: "0.5s" }}
          >
            <Card className="max-w-2xl mx-auto border-primary/20 bg-gradient-to-br from-primary/5 to-cyan-400/5">
              <CardContent className="p-8">
                <div className="flex items-center justify-center gap-3 mb-4">
                  <LogoIcon className="w-10 h-10" />
                </div>
                <h3 className="text-2xl font-bold mb-2 text-foreground">
                  Ready to Get Started?
                </h3>
                <p className="text-neutral-500 mb-6 max-w-md mx-auto">
                  Join thousands of businesses already using NexaBot to provide
                  instant, AI-powered customer support.
                </p>

                <div className="flex flex-col sm:flex-row gap-3 justify-center">
                  <Button
                    size="lg"
                    className="h-14 px-10 bg-primary text-white hover:bg-primary/90 shadow-md hover:shadow-lg active:scale-[0.98] transition-all text-base font-semibold rounded-xl"
                    onClick={() => navigate("/signup")}
                  >
                    Start Free Beta
                    <ArrowRight className="w-5 h-5 ml-2" />
                  </Button>
                </div>

                <p className="text-xs text-neutral-400 mt-4">
                  No credit card required. Setup in under 5 minutes.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HowItWorks;
