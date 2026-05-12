import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Globe,
  MessageSquare,
  Slack,
  Github,
  FileText,
  Zap,
  ArrowUpRight,
} from "lucide-react";

const integrations = [
  {
    name: "Website Widget",
    desc: "Embed a smart AI assistant on your website in minutes with a single script tag.",
    icon: Globe,
    status: "active" as const,
    color: "text-primary",
    bgColor: "bg-primary/10",
  },
  {
    name: "WhatsApp",
    desc: "Connect your WhatsApp Business API for automated customer conversations.",
    icon: MessageSquare,
    status: "active" as const,
    color: "text-emerald-600",
    bgColor: "bg-emerald-500/10",
  },
  {
    name: "Messenger",
    desc: "Deploy on Facebook Messenger to engage customers where they already chat.",
    icon: MessageSquare,
    status: "active" as const,
    color: "text-blue-600",
    bgColor: "bg-blue-500/10",
  },
  {
    name: "Slack",
    desc: "Bring AI-powered responses directly into your team communication channels.",
    icon: Slack,
    status: "active" as const,
    color: "text-violet-600",
    bgColor: "bg-violet-500/10",
  },
  {
    name: "Discord",
    desc: "Add NexaBot to your Discord server for community and support automation.",
    icon: MessageSquare,
    status: "active" as const,
    color: "text-indigo-600",
    bgColor: "bg-indigo-500/10",
  },
  {
    name: "API Access",
    desc: "Build custom integrations with our REST API and webhook system.",
    icon: Zap,
    status: "active" as const,
    color: "text-amber-600",
    bgColor: "bg-amber-500/10",
  },
];

const IntegrationsSection = () => {
  return (
    <section
      id="integrations"
      className="py-24 bg-background relative overflow-hidden"
    >
      <div className="absolute inset-0">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-gradient-radial from-primary/3 to-transparent rounded-full blur-3xl" />
      </div>

      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="text-center mb-16 max-w-2xl mx-auto space-y-4 animate-fade-up">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/8 border border-primary/15 text-primary text-xs font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-primary" />
            Integrations
          </div>
          <h2 className="text-4xl lg:text-5xl font-bold tracking-tight text-foreground">
            Deploy Anywhere Your
            <span className="gradient-text block">Customers Are</span>
          </h2>
          <p className="text-lg text-neutral-500 leading-relaxed">
            One platform, every channel. NexaBot works with all major messaging
            platforms and can be extended via API.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-w-5xl mx-auto">
          {integrations.map((item, i) => (
            <div
              key={i}
              className="animate-fade-up group"
              style={{ animationDelay: `${i * 0.06}s` }}
            >
              <Card className="h-full border-border/40 hover:border-border/70 transition-all duration-300 hover:shadow-md cursor-default">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <div
                    className={`w-10 h-10 rounded-xl ${item.bgColor} flex items-center justify-center group-hover:scale-110 transition-transform duration-300`}
                  >
                    <item.icon className={`w-5 h-5 ${item.color}`} />
                  </div>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-success-50 text-success-700 text-[10px] font-medium">
                    <span className="w-1 h-1 rounded-full bg-success-500" />
                    Live
                  </span>
                </CardHeader>
                <CardContent>
                  <CardTitle className="text-sm font-semibold mb-1.5">
                    {item.name}
                  </CardTitle>
                  <p className="text-xs text-neutral-500 leading-relaxed">
                    {item.desc}
                  </p>
                </CardContent>
              </Card>
            </div>
          ))}
        </div>

        {/* API Note */}
        <div
          className="text-center mt-10 animate-fade-up"
          style={{ animationDelay: "0.4s" }}
        >
          <p className="text-sm text-neutral-400">
            All integrations are included in the beta plan. No additional setup
            fees.
          </p>
        </div>
      </div>
    </section>
  );
};

export default IntegrationsSection;
