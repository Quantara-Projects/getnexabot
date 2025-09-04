import { Bot, Mail, MessageSquare, Twitter, Linkedin, Github } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Link, useNavigate } from 'react-router-dom';

const Footer = () => {
  const navigate = useNavigate();

  const footerLinks = {
    Product: [
      { name: 'Features', href: '#features' },
      { name: 'Pricing', href: '#pricing' },
      { name: 'Demo', href: '#demo' },
      { name: 'Integrations', href: '#integrations' }
    ],
    Company: [
      { name: 'About', href: '#about' },
      { name: 'Blog', href: '#blog' },
      { name: 'Careers', href: '#careers' },
      { name: 'Contact', href: '#contact' }
    ],
    Legal: [
      { name: 'Privacy Policy', to: '/privacy' },
      { name: 'Terms of Service', to: '/terms' },
      { name: 'Cookie Policy', to: '/cookies' },
      { name: 'GDPR', to: '/gdpr' }
    ],
    Support: [
      { name: 'Help Center', to: '/help' },
      { name: 'API Docs', to: '/api' },
      { name: 'Status', to: '/status' },
      { name: 'Community', to: '/community' }
    ]
  } as const;

  const socialLinks = [
    { icon: Twitter, href: '#', label: 'Twitter' },
    { icon: Linkedin, href: '#', label: 'LinkedIn' },
    { icon: Github, href: '#', label: 'GitHub' }
  ];

  return (
    <footer className="bg-muted/30 border-t">
      {/* CTA Banner */}
      <div className="bg-gradient-to-r from-primary to-violet-600 text-white py-12">
        <div className="container mx-auto px-6 text-center">
          <h2 className="text-3xl lg:text-4xl font-bold mb-4">
            Start Replying Instantly – Your Customers Are Waiting
          </h2>
          <p className="text-xl text-white/90 mb-8 max-w-2xl mx-auto">
            Join hundreds of businesses providing 24/7 AI-powered customer support. Get started for free today.
          </p>
          <Button 
            size="lg"
            className="h-14 px-8 bg-white text-primary hover:bg-white/90 text-lg font-semibold shadow-lg"
            onClick={() => navigate('/signup')}
          >
            Sign Up Free – Beta Access
          </Button>
        </div>
      </div>

      <div className="container mx-auto px-6 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-6 gap-8">
          {/* Brand Section */}
          <div className="lg:col-span-2">
            <div className="flex items-center space-x-3 mb-6">
              <div className="w-10 h-10 bg-gradient-to-r from-primary to-violet-600 rounded-lg flex items-center justify-center">
                <Bot className="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 className="text-2xl font-bold">NexaBot</h3>
                <p className="text-sm text-muted-foreground">AI-Powered Customer Support</p>
              </div>
            </div>
            
            <p className="text-muted-foreground mb-6 leading-relaxed">
              Never miss a customer again with AI chatbots that provide instant, 24/7 support across all your channels.
            </p>
            
            <div className="flex items-center space-x-4">
              {socialLinks.map((social, index) => (
                <a
                  key={index}
                  href={social.href}
                  className="w-10 h-10 bg-secondary rounded-lg flex items-center justify-center hover:bg-primary hover:text-white transition-smooth"
                  aria-label={social.label}
                >
                  <social.icon className="w-5 h-5" />
                </a>
              ))}
            </div>
          </div>

          {/* Links Sections */}
          {Object.entries(footerLinks).map(([category, links]) => (
            <div key={category}>
              <h4 className="font-semibold mb-4">{category}</h4>
              <ul className="space-y-3">
                {links.map((link, index) => (
                  <li key={index}>
                    <Link
                      to={link.to}
                      className="text-muted-foreground hover:text-foreground transition-smooth text-sm"
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom Section */}
        <div className="border-t pt-8 mt-12">
          <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
            <div className="text-sm text-muted-foreground">
              © 2024 NexaBot. All rights reserved.
            </div>
            
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span>All systems operational</span>
              </div>
              
              <div className="flex items-center space-x-4">
                <a 
                  href="mailto:hello@nexabot.ai"
                  className="flex items-center space-x-2 text-sm text-muted-foreground hover:text-foreground transition-smooth"
                >
                  <Mail className="w-4 h-4" />
                  <span>hello@nexabot.ai</span>
                </a>
                
                <Link
                  to="/help"
                  className="flex items-center space-x-2 text-sm text-muted-foreground hover:text-foreground transition-smooth"
                >
                  <MessageSquare className="w-4 h-4" />
                  <span>Live Chat</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
