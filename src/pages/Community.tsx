import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";
import { MessageSquare, Lightbulb, Rocket } from "lucide-react";

const Community = () => (
  <PageShell
    eyebrow="Community"
    title="Build with the NexaBot community"
    description="The community is where beta users share feedback, request features, and help shape the product before launch."
  >
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[
        { icon: MessageSquare, title: "Feedback", text: "Tell us where the setup flow is unclear and what your customers ask most." },
        { icon: Lightbulb, title: "Feature requests", text: "Beta users get priority on practical channel, training, and analytics requests." },
        { icon: Rocket, title: "Early access", text: "New integrations and Web3 subscription tools will be opened to beta users first." },
      ].map((item) => (
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

export default Community;
