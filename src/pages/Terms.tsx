import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";

const terms = [
  ["Service use", "You may use NexaBot to create and deploy AI support assistants for your own business or authorized clients."],
  ["Customer data", "You are responsible for the website content, uploaded files, and instructions used to train your bot."],
  ["Acceptable use", "Do not use NexaBot for spam, impersonation, malware, credential theft, harassment, illegal activity, or deceptive automation."],
  ["Ownership", "NexaBot, its product design, code, and branding are owned by Trakory, Inc."],
  ["Beta access", "Beta features may change while the platform is improved. Beta users receive three months of free trial access."],
];

const Terms = () => (
  <PageShell
    eyebrow="Legal"
    title="Terms of Service"
    description="These terms govern access to NexaBot, an AI customer support platform owned by Trakory, Inc."
  >
    <div className="space-y-4">
      {terms.map(([title, text]) => (
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

export default Terms;
