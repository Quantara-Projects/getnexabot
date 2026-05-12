import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";

const sections = [
  ["Information we collect", "Account details, business profile data, website URLs, uploaded training content, widget usage, and support messages."],
  ["How we use it", "To provide chatbot training, widget deployment, account security, support, analytics, and service improvements."],
  ["AI processing", "Customer questions and configured training data may be sent to AI providers to generate responses for your bot."],
  ["Data control", "Account owners can request export or deletion of their account and training data."],
];

const PrivacyPolicy = () => (
  <PageShell
    eyebrow="Legal"
    title="Privacy Policy"
    description="NexaBot is owned by Trakory, Inc. This policy explains how we handle account, training, and chatbot data."
  >
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {sections.map(([title, text]) => (
        <Card key={title} className="border-border/40">
          <CardContent className="p-6">
            <h2 className="font-semibold mb-2">{title}</h2>
            <p className="text-sm text-neutral-500 leading-relaxed">{text}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  </PageShell>
);

export default PrivacyPolicy;
