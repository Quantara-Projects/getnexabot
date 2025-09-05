import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Reveal } from '@/hooks/use-in-view';
import { Bot, Briefcase, Mail, Newspaper, Shield, Rocket, Users, BookOpen } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const CompanySections = () => {
  const navigate = useNavigate();
  return (
    <section className="py-20 bg-background">
      <div className="container mx-auto px-6 grid gap-12">
        {/* About */}
        <div id="about">
          <Reveal className="text-center mb-6">
            <h2 className="text-4xl lg:text-5xl font-bold mb-4">About Us</h2>
            <p className="text-xl text-muted-foreground max-w-4xl mx-auto">At NexaBot, we believe AI should be accessible, secure, and powerful enough to simplify lives.</p>
          </Reveal>
          <Reveal>
            <Card>
              <CardContent className="space-y-4 pt-6 text-muted-foreground">
                <p>Our journey began with a simple idea: what if every individual and business could have an intelligent assistant that understands their needs, adapts to their workflows, and integrates seamlessly into their daily tools?</p>
                <p>Founded in 2025, we set out to build an AI platform that combines cutting-edge natural language processing with enterprise-grade security. Today, NexoBot is trusted by students, freelancers, and companies to handle everyday tasks—from analyzing documents to automating customer support.</p>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div className="flex items-start space-x-3"><Rocket className="w-5 h-5 text-primary mt-0.5" /><p><b>Innovation First</b> – pushing the boundaries of what AI can achieve.</p></div>
                  <div className="flex items-start space-x-3"><Shield className="w-5 h-5 text-primary mt-0.5" /><p><b>Security Always</b> – protecting user data through encryption and strict compliance.</p></div>
                  <div className="flex items-start space-x-3"><BookOpen className="w-5 h-5 text-primary mt-0.5" /><p><b>Transparency & Trust</b> – being honest about how our AI works and what it does.</p></div>
                  <div className="flex items-start space-x-3"><Users className="w-5 h-5 text-primary mt-0.5" /><p><b>Community Driven</b> – listening to users and improving through feedback.</p></div>
                </div>
                <p>We are more than just a tool. We are building the future of human-AI collaboration.</p>
              </CardContent>
            </Card>
          </Reveal>
        </div>

        {/* Blog overview */}
        <div id="blog">
          <Reveal className="text-center mb-6">
            <h2 className="text-3xl lg:text-4xl font-bold mb-2">Blog</h2>
            <p className="text-muted-foreground">Insights, tutorials, and the latest updates.</p>
          </Reveal>
          <Reveal>
            <Card>
              <CardContent className="pt-6 text-muted-foreground">
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="font-semibold mb-2">Categories</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      <li>Product Updates</li>
                      <li>Guides & Tutorials</li>
                      <li>AI & Technology Trends</li>
                      <li>Community Highlights</li>
                    </ul>
                  </div>
                  <div>
                    <h3 className="font-semibold mb-2">Recent Posts</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      <li>How AI Is Transforming Remote Work in 2025</li>
                      <li>5 Ways to Supercharge Your Customer Support with AI</li>
                      <li>Step-by-Step: Training Your NexoBot on Company Documents</li>
                    </ul>
                  </div>
                </div>
                <Button variant="outline" className="mt-6" onClick={() => navigate('/blog')}>Visit Blog</Button>
              </CardContent>
            </Card>
          </Reveal>
        </div>

        {/* Careers */}
        <div id="careers">
          <Reveal className="text-center mb-6">
            <h2 className="text-3xl lg:text-4xl font-bold mb-2">Careers</h2>
            <p className="text-muted-foreground">We’re building the future of AI-driven productivity—and we want you to be part of it.</p>
          </Reveal>
          <Reveal>
            <Card>
              <CardContent className="pt-6 text-muted-foreground space-y-4">
                <p>Our culture is remote-first, inclusive, growth-focused, and mission-driven.</p>
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="font-semibold mb-2">Current Openings</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      <li>AI Engineer</li>
                      <li>Frontend Developer (React/TypeScript)</li>
                      <li>Backend Engineer (Node.js, Express, PostgreSQL)</li>
                      <li>Product Designer</li>
                      <li>Content Writer</li>
                    </ul>
                  </div>
                  <div>
                    <h3 className="font-semibold mb-2">Perks & Benefits</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      <li>Competitive salary</li>
                      <li>Health & wellness support</li>
                      <li>Stock options</li>
                      <li>Team retreats and hackathons</li>
                    </ul>
                  </div>
                </div>
                <Button className="mt-2" onClick={() => navigate('/contact')}>Apply or Contact Us</Button>
              </CardContent>
            </Card>
          </Reveal>
        </div>

        {/* Contact */}
        <div id="contact">
          <Reveal className="text-center mb-6">
            <h2 className="text-3xl lg:text-4xl font-bold mb-2">Contact</h2>
            <p className="text-muted-foreground">We’d love to hear from you.</p>
          </Reveal>
          <Reveal>
            <Card>
              <CardContent className="pt-6 text-muted-foreground space-y-3">
                <p>General: support@nexobot.ai</p>
                <p>Business/partnerships: business@nexobot.ai</p>
                <p>Press: press@nexobot.ai</p>
                <Button variant="outline" className="mt-2" onClick={() => navigate('/contact')}>Open Contact Form</Button>
              </CardContent>
            </Card>
          </Reveal>
        </div>
      </div>
    </section>
  );
};

export default CompanySections;
