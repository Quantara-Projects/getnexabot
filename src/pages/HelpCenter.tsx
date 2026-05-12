import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";

const topics = [
  ["Create a bot", "Open Dashboard, complete the three-step setup, then confirm the bot."],
  ["Install the widget", "Copy the generated script and place it before the closing body tag on the approved website."],
  ["Train responses", "Add a required company description and optional documents so the AI has business-specific context."],
  ["Local testing", "Choose Localhost or Both in the wizard when testing during development."],
];

const HelpCenter = () => (
  <PageShell
    eyebrow="Support"
    title="Help Center"
    description="Quick answers for setting up, training, and installing NexaBot."
  >
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {topics.map(([title, text]) => (
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

export default HelpCenter;
