import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";

const CookiePolicy = () => (
  <PageShell
    eyebrow="Legal"
    title="Cookie Policy"
    description="NexaBot uses limited cookies and local storage to keep accounts signed in, remember preferences, and protect the service."
  >
    <Card className="border-border/40">
      <CardContent className="p-6 space-y-4 text-sm text-neutral-500 leading-relaxed">
        <p>Essential cookies support login, security, and dashboard sessions.</p>
        <p>Preference storage may remember UI choices such as theme, setup progress, and dashboard state.</p>
        <p>We do not sell personal data. You can clear cookies in your browser, but some account features may stop working until you sign in again.</p>
      </CardContent>
    </Card>
  </PageShell>
);

export default CookiePolicy;
