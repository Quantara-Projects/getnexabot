import {
  Bot,
  MessageSquare,
  FileSpreadsheet,
  GraduationCap,
  Shield,
  Palette,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

const features = [
  {
    icon: Bot,
    title: "AI Chat Assistant",
    desc: "Natural conversations to answer questions, qualify leads, and resolve issues instantly.",
    gradient: "from-primary/10 to-cyan-400/10",
    iconBg: "bg-primary/10",
    iconColor: "text-primary",
  },
  {
    icon: FileSpreadsheet,
    title: "Document Analyzer",
    desc: "Upload PDFs, DOCX, or TXT files. NexaBot learns your business data automatically.",
    gradient: "from-emerald-500/10 to-teal-400/10",
    iconBg: "bg-emerald-500/10",
    iconColor: "text-emerald-600",
  },
  {
    icon: GraduationCap,
    title: "Custom Bot Training",
    desc: "Train your AI on FAQs, website content, or company knowledge. No coding required.",
    gradient: "from-violet-500/10 to-purple-400/10",
    iconBg: "bg-violet-500/10",
    iconColor: "text-violet-600",
  },
  {
    icon: MessageSquare,
    title: "Omnichannel Support",
    desc: "Deploy across website widget, WhatsApp, Messenger, Slack, and Discord from one dashboard.",
    gradient: "from-blue-500/10 to-sky-400/10",
    iconBg: "bg-blue-500/10",
    iconColor: "text-blue-600",
  },
  {
    icon: Shield,
    title: "Security by Design",
    desc: "End-to-end encryption, GDPR compliance, and strict data privacy policies out of the box.",
    gradient: "from-amber-500/10 to-orange-400/10",
    iconBg: "bg-amber-500/10",
    iconColor: "text-amber-600",
  },
  {
    icon: Palette,
    title: "Customizable UI",
    desc: "Personalize your chatbot's appearance, greeting, colors, and behavior to match your brand.",
    gradient: "from-rose-500/10 to-pink-400/10",
    iconBg: "bg-rose-500/10",
    iconColor: "text-rose-600",
  },
];

const FeaturesSection = () => {
  return (
    <section
      id="features"
      className="py-24 bg-background relative overflow-hidden"
    >
      {/* Background decoration */}
      <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-border to-transparent" />

      <div className="container mx-auto px-6">
        {/* Section Header */}
        <div className="text-center mb-16 max-w-2xl mx-auto space-y-4 animate-fade-up">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/8 border border-primary/15 text-primary text-xs font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-primary" />
            Platform Features
          </div>
          <h2 className="text-4xl lg:text-5xl font-bold tracking-tight text-foreground">
            Everything You Need to
            <span className="gradient-text block">Automate Support</span>
          </h2>
          <p className="text-lg text-neutral-500 leading-relaxed">
            NexaBot combines AI intelligence with omnichannel reach to deliver
            instant, personalized customer support at scale.
          </p>
        </div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {features.map((f, i) => (
            <div
              key={i}
              className="animate-fade-up group"
              style={{ animationDelay: `${i * 0.08}s` }}
            >
              <Card className="h-full border-border/50 hover:border-border/80 transition-all duration-300 hover:shadow-md">
                <CardHeader className="flex flex-row items-center gap-4 pb-3">
                  <div
                    className={`w-11 h-11 rounded-xl ${f.iconBg} flex items-center justify-center group-hover:scale-110 transition-transform duration-300`}
                  >
                    <f.icon className={`w-5.5 h-5.5 ${f.iconColor}`} />
                  </div>
                  <CardTitle className="text-base font-semibold">
                    {f.title}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-neutral-500 leading-relaxed">
                    {f.desc}
                  </p>
                </CardContent>
              </Card>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
