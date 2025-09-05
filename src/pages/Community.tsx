import { ArrowLeft, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate } from 'react-router-dom';

const Community = () => {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Button variant="ghost" onClick={() => navigate('/')} className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4 mr-2" /> Home
          </Button>
          <div className="flex items-center space-x-2">
            <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg"><Users className="w-5 h-5 text-white" /></div>
            <h1 className="text-lg font-bold">Community</h1>
          </div>
        </div>
      </header>
      <div className="container mx-auto px-6 py-10">
        <Card>
          <CardHeader>
            <CardTitle>Community</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-muted-foreground">
            <p>We’re building more than a product—we’re building a movement.</p>
            <div>
              <h3 className="font-semibold mb-2">Join the NexaBot community to</h3>
              <ul className="list-disc pl-5 space-y-1">
                <li>Share ideas – Suggest features or improvements.</li>
                <li>Learn together – Tutorials, webinars, and peer-to-peer support.</li>
                <li>Get early access – Beta programs and experimental tools.</li>
                <li>Connect globally – Developers, businesses, and AI enthusiasts worldwide.</li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold mb-2">Our community lives on</h3>
              <ul className="list-disc pl-5 space-y-1">
                <li>Discord – Real-time discussion.</li>
                <li>Forum – Long-form Q&A.</li>
                <li>Events – Monthly webinars and hackathons.</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Community;
