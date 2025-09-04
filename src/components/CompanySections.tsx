import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Reveal } from '@/hooks/use-in-view';
import { Bot, Briefcase, Mail, Newspaper } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const CompanySections = () => {
  const navigate = useNavigate();
  return (
    <section className="py-20 bg-background">
      <div className="container mx-auto px-6 grid gap-10" id="about">
        <Reveal className="text-center">
          <h2 className="text-4xl lg:text-5xl font-bold mb-4">About NexaBot</h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">We help businesses deliver instant, always-on support with delightful customer experiences.</p>
        </Reveal>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6" id="blog">
          <Reveal>
            <Card>
              <CardHeader className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-primary/10 text-primary rounded-lg flex items-center justify-center"><Bot className="w-5 h-5" /></div>
                <CardTitle>Our Mission</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">Make world-class support accessible to every business, regardless of size.</p>
              </CardContent>
            </Card>
          </Reveal>
          <Reveal>
            <Card>
              <CardHeader className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-primary/10 text-primary rounded-lg flex items-center justify-center"><Newspaper className="w-5 h-5" /></div>
                <CardTitle>From the Blog</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">Product updates, customer stories, and best practices.</p>
                <Button variant="outline" className="mt-3" onClick={() => navigate('/blog')}>Read Blog</Button>
              </CardContent>
            </Card>
          </Reveal>
          <Reveal>
            <Card id="careers">
              <CardHeader className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-primary/10 text-primary rounded-lg flex items-center justify-center"><Briefcase className="w-5 h-5" /></div>
                <CardTitle>Careers</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">We are hiring remote-first builders. Join us to shape the future of support.</p>
                <Button variant="outline" className="mt-3" onClick={() => navigate('/careers')}>See Roles</Button>
              </CardContent>
            </Card>
          </Reveal>
        </div>

        <Reveal>
          <Card id="contact" className="mt-4">
            <CardHeader>
              <CardTitle>Contact Us</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">Have questions or need help getting started?</p>
              <Button onClick={() => navigate('/contact')}>
                <Mail className="w-4 h-4 mr-2" />
                Get in touch
              </Button>
            </CardContent>
          </Card>
        </Reveal>
      </div>
    </section>
  );
};

export default CompanySections;
