import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const systems = ["Website", "Dashboard", "Widget API", "AI Responses", "Supabase"];

const Status = () => (
  <PageShell
    eyebrow="Support"
    title="System Health"
    description="Current public status for NexaBot services. Testnet details are shown here when relevant, not in primary marketing sections."
  >
    <div className="space-y-3">
      {systems.map((system) => (
        <Card key={system} className="border-border/40">
          <CardContent className="p-4 flex items-center justify-between">
            <span className="font-medium">{system}</span>
            <Badge className="bg-primary/10 text-primary border-primary/20">
              Operational
            </Badge>
          </CardContent>
        </Card>
      ))}
      <p className="text-sm text-neutral-400">Built on LitVM Ecosystem support is tracked as part of subscription and payment releases.</p>
    </div>
  </PageShell>
);

export default Status;
