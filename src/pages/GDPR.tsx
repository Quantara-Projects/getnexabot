import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";

const GDPR = () => (
  <PageShell
    eyebrow="Legal"
    title="GDPR"
    description="NexaBot is designed to help businesses manage customer support data responsibly."
  >
    <Card className="border-border/40">
      <CardContent className="p-6 space-y-4 text-sm text-neutral-500 leading-relaxed">
        <p>Account owners can request access, correction, export, or deletion of personal data associated with their account.</p>
        <p>Uploaded training data is used to operate the chatbot configured by the account owner. Owners are responsible for ensuring they have permission to upload that information.</p>
        <p>For privacy requests, contact hello@nexabot.ai with the account email and request type.</p>
      </CardContent>
    </Card>
  </PageShell>
);

export default GDPR;
