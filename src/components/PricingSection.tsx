import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Check, ArrowRight, Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { LogoIcon } from "@/components/ui/logo";

const PricingSection = () => {
  const navigate = useNavigate();

  const betaFeatures = [
    "Unlimited conversations",
    "Website chat widget",
    "WhatsApp integration",
    "Messenger integration",
    "Slack & Discord support",
    "Lead capture & notifications",
    "Custom AI training",
    "Analytics dashboard",
    "Email support",
  ];

  return (
    <section
      id="pricing"
      className="py-24 bg-secondary/20 relative overflow-hidden"
    >
      <div className="absolute inset-0">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-gradient-radial from-primary/4 to-transparent rounded-full blur-3xl" />
      </div>

      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="text-center mb-16 max-w-2xl mx-auto space-y-4 animate-fade-up">
          <Badge className="bg-primary/10 text-primary border-primary/20 text-xs font-medium px-3 py-1.5">
            Beta Access - Limited Time
          </Badge>

          <h2 className="text-4xl lg:text-5xl font-bold tracking-tight text-foreground">
            Free During
            <span className="gradient-text block">Beta</span>
          </h2>

          <p className="text-lg text-neutral-500 leading-relaxed">
            Get full access to all NexaBot features during our beta period. No
            payment required, no hidden fees.
          </p>
        </div>

        <div className="max-w-4xl mx-auto">
          {/* Beta Plan */}
          <div className="animate-fade-up" style={{ animationDelay: "0.15s" }}>
            <Card className="relative overflow-hidden border-2 border-primary/20 shadow-xl">
              {/* Beta Badge */}
              <div className="absolute top-0 right-0 gradient-bg text-white px-8 py-1.5 transform rotate-12 translate-x-6 translate-y-5">
                <span className="font-bold text-xs tracking-wider">
                  FREE BETA
                </span>
              </div>

              <CardHeader className="text-center pb-2 pt-8">
                <div className="flex justify-center mb-4">
                  <LogoIcon className="w-16 h-16" />
                </div>

                <CardTitle className="text-3xl font-bold text-foreground">
                  Beta Access Plan
                </CardTitle>
                <div className="text-5xl font-bold text-primary my-4">
                  Free
                  <span className="text-base text-neutral-400 font-normal ml-2">
                    during beta
                  </span>
                </div>
                <p className="text-neutral-500">
                  Full access to all features while we perfect the platform
                </p>
              </CardHeader>

              <CardContent className="px-8 pb-8">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Features List */}
                  <div>
                    <h4 className="text-sm font-semibold text-foreground mb-3">
                      Everything included:
                    </h4>
                    <ul className="space-y-2.5">
                      {betaFeatures.map((feature, index) => (
                        <li key={index} className="flex items-center gap-2.5">
                          <Check className="w-4 h-4 text-primary flex-shrink-0" />
                          <span className="text-sm text-neutral-600">
                            {feature}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Benefits */}
                  <div className="bg-primary/5 rounded-xl p-5 border border-primary/10">
                    <h4 className="text-sm font-semibold text-primary mb-3">
                      Beta Benefits:
                    </h4>
                    <ul className="space-y-2.5">
                      <li className="flex items-center gap-2.5 text-sm text-neutral-600">
                        <Clock className="w-4 h-4 text-primary flex-shrink-0" />
                        <span>3 months free trial</span>
                      </li>
                      <li className="flex items-center gap-2.5 text-sm text-neutral-600">
                        <Check className="w-4 h-4 text-primary flex-shrink-0" />
                        <span>Priority feature requests</span>
                      </li>
                      <li className="flex items-center gap-2.5 text-sm text-neutral-600">
                        <Check className="w-4 h-4 text-primary flex-shrink-0" />
                        <span>Direct feedback to founders</span>
                      </li>
                      <li className="flex items-center gap-2.5 text-sm text-neutral-600">
                        <Check className="w-4 h-4 text-primary flex-shrink-0" />
                        <span>Early access to new features</span>
                      </li>
                    </ul>
                  </div>
                </div>

                <div className="mt-8 text-center">
                  <Button
                    size="lg"
                    className="h-14 px-10 bg-primary text-white hover:bg-primary/90 shadow-md hover:shadow-lg active:scale-[0.98] transition-all text-base font-semibold rounded-xl"
                    onClick={() => navigate("/signup")}
                  >
                    Get Free Beta Access
                    <ArrowRight className="w-5 h-5 ml-2" />
                  </Button>

                  <p className="text-xs text-neutral-400 mt-3">
                    No credit card required. Cancel anytime.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </section>
  );
};

export default PricingSection;
