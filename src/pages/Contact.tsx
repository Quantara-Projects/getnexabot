import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Mail, MessageSquare, Clock } from "lucide-react";

const Contact = () => (
  <PageShell
    eyebrow="Contact"
    title="Talk to NexaBot"
    description="Questions about setup, beta access, integrations, offers, or billing can be sent directly to the team."
  >
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
      <Card className="lg:col-span-2 border-border/40">
        <CardContent className="p-6 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <Label>Name</Label>
              <Input className="mt-1.5" placeholder="Your name" />
            </div>
            <div>
              <Label>Email</Label>
              <Input
                className="mt-1.5"
                type="email"
                placeholder="you@company.com"
              />
            </div>
          </div>
          <div>
            <Label>Message</Label>
            <Textarea
              className="mt-1.5 min-h-[140px]"
              placeholder="How can we help?"
            />
          </div>
          <Button className="bg-primary hover:bg-primary/90 text-white">
            Send Message
          </Button>
        </CardContent>
      </Card>

      <div className="space-y-4">
        {[
          { icon: Mail, title: "Email", text: "contact@getnexabot.me" },
          {
            icon: Clock,
            title: "Response window",
            text: "Beta support replies as quickly as possible.",
          },
          {
            icon: MessageSquare,
            title: "Best for",
            text: "Setup help, account questions, and product feedback.",
          },
        ].map((item) => (
          <Card key={item.title} className="border-border/40">
            <CardContent className="p-5">
              <item.icon className="w-5 h-5 text-primary mb-3" />
              <h2 className="font-semibold">{item.title}</h2>
              <p className="text-sm text-neutral-500 mt-1">{item.text}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  </PageShell>
);

export default Contact;
