import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";

const ApiDocs = () => (
  <PageShell
    eyebrow="Developers"
    title="API Docs"
    description="Use the widget script to install a confirmed NexaBot assistant on an approved website."
  >
    <Card className="border-border/40">
      <CardContent className="p-6 space-y-4">
        <div>
          <h2 className="font-semibold mb-2">Website widget</h2>
          <p className="text-sm text-neutral-500">
            Each confirmed bot receives a public widget key. The key identifies the bot but does not expose server API secrets.
          </p>
        </div>
        <pre className="overflow-x-auto rounded-lg bg-foreground text-background p-4 text-xs">
{`<script async
  src="http://localhost:8080/api/nexabot"
  data-bot-id="bot_example"
  data-api-key="nxb_public_widget_key">
</script>`}
        </pre>
        <div>
          <h2 className="font-semibold mb-2">Security</h2>
          <p className="text-sm text-neutral-500">
            Live widgets are checked against the configured website domain. Localhost mode is only for development.
          </p>
        </div>
      </CardContent>
    </Card>
  </PageShell>
);

export default ApiDocs;
