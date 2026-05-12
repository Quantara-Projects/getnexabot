import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";
import { Shield, Zap, Globe, MessageSquare } from "lucide-react";

const About = () => {
  const principles = [
    {
      icon: Zap,
      title: "Fast support without extra headcount",
      text: "NexaBot helps businesses answer common questions, qualify leads, and guide customers around the clock.",
    },
    {
      icon: Shield,
      title: "Business knowledge stays central",
      text: "Each bot is trained from the company website, documents, and owner-written instructions so responses stay on brand.",
    },
    {
      icon: Globe,
      title: "Built for every customer channel",
      text: "Website chat is available now. WhatsApp, Messenger, Slack, and Discord are planned as controlled channel releases.",
    },
    {
      icon: MessageSquare,
      title: "Owned by Trakory, Inc.",
      text: "NexaBot is developed and operated by Trakory, Inc. as an AI support platform for modern businesses.",
    },
  ];

  return (
    <PageShell
      eyebrow="Company"
      title="About NexaBot"
      description="NexaBot is an AI customer support and automation platform for businesses that need reliable 24/7 replies, lead capture, and simple deployment."
    >
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {principles.map((item) => (
          <Card key={item.title} className="border-border/40">
            <CardContent className="p-6">
              <item.icon className="w-6 h-6 text-primary mb-4" />
              <h2 className="font-semibold text-lg mb-2">{item.title}</h2>
              <p className="text-sm text-neutral-500 leading-relaxed">{item.text}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </PageShell>
  );
};

export default About;
