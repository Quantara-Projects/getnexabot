import { LogoIcon, LogoText } from "@/components/ui/logo";
import { Mail, MessageSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link, useNavigate } from "react-router-dom";

const Footer = () => {
  const navigate = useNavigate();
  const currentYear = new Date().getFullYear();

  const footerLinks = {
    Product: [
      { name: "Features", href: "#features" },
      { name: "Pricing", href: "#pricing" },
      { name: "Demo", href: "#demo" },
      { name: "Integrations", href: "#integrations" },
    ],
    Company: [
      { name: "About", to: "/about" },
      { name: "Blog", to: "/blog" },
      { name: "Contact", to: "/contact" },
      { name: "Community", to: "/community" },
    ],
    Legal: [
      { name: "Privacy Policy", to: "/privacy" },
      { name: "Terms of Service", to: "/terms" },
      { name: "Cookie Policy", to: "/cookies" },
      { name: "GDPR", to: "/gdpr" },
    ],
    Support: [
      { name: "Help Center", to: "/help" },
      { name: "API Docs", to: "/api" },
      { name: "Status", to: "/status" },
      { name: "System Health", to: "/status" },
    ],
  } as const;

  return (
    <footer className="border-t border-border/40 bg-background">
      {/* CTA Banner */}
      <div className="gradient-bg text-white py-12">
        <div className="container mx-auto px-6 text-center">
          <h2 className="text-3xl lg:text-4xl font-bold mb-3 tracking-tight">
            Your Customers Are Waiting
          </h2>
          <p className="text-lg text-white/80 mb-6 max-w-xl mx-auto">
            Join thousands of businesses providing 24/7 AI-powered customer
            support. Get started for free.
          </p>
          <Button
            size="lg"
            className="h-12 px-8 bg-white text-primary hover:bg-white/90 text-base font-semibold shadow-sm hover:shadow-md active:scale-[0.98] transition-all"
            onClick={() => navigate("/signup")}
          >
            Sign Up Free - Beta Access
          </Button>
        </div>
      </div>

      <div className="container mx-auto px-6 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-6 gap-10">
          {/* Brand Section */}
          <div className="lg:col-span-2">
            <div
              className="flex items-center gap-3 mb-4 cursor-pointer group"
              onClick={() => navigate("/")}
            >
              <LogoIcon className="w-9 h-9" />
              <div>
                <LogoText className="text-xl" />
                <p className="text-xs text-neutral-400">
                  AI-Powered Customer Support
                </p>
              </div>
            </div>

            <p className="text-sm text-neutral-500 mb-6 leading-relaxed max-w-xs">
              Never miss a customer again with AI chatbots that provide instant,
              24/7 support across all your channels. NexaBot is owned by
              Trakory, Inc.
            </p>

            <div className="flex items-center gap-3">
              <a
                href="#"
                className="w-9 h-9 rounded-lg bg-secondary flex items-center justify-center hover:bg-primary hover:text-white transition-smooth"
                aria-label="Twitter"
              >
                <svg viewBox="0 0 24 24" className="w-4 h-4 fill-current">
                  <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
                </svg>
              </a>
              <a
                href="#"
                className="w-9 h-9 rounded-lg bg-secondary flex items-center justify-center hover:bg-primary hover:text-white transition-smooth"
                aria-label="LinkedIn"
              >
                <svg viewBox="0 0 24 24" className="w-4 h-4 fill-current">
                  <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
                </svg>
              </a>
              <a
                href="#"
                className="w-9 h-9 rounded-lg bg-secondary flex items-center justify-center hover:bg-primary hover:text-white transition-smooth"
                aria-label="GitHub"
              >
                <svg viewBox="0 0 24 24" className="w-4 h-4 fill-current">
                  <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
                </svg>
              </a>
            </div>
          </div>

          {/* Links Sections */}
          {Object.entries(footerLinks).map(([category, links]) => (
            <div key={category}>
              <h4 className="text-sm font-semibold text-foreground mb-4">
                {category}
              </h4>
              <ul className="space-y-2.5">
                {links.map((link, index) => (
                  <li key={index}>
                    {"href" in link ? (
                      <a
                        href={link.href}
                        className="text-sm text-neutral-500 hover:text-foreground transition-smooth"
                      >
                        {link.name}
                      </a>
                    ) : (
                      <Link
                        to={(link as any).to}
                        className="text-sm text-neutral-500 hover:text-foreground transition-smooth"
                      >
                        {link.name}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom Section */}
        <div className="border-t border-border/40 pt-8 mt-10">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="text-sm text-neutral-400">
              &copy; {currentYear} NexaBot. All rights reserved. Owned by
              Trakory, Inc.
            </div>

            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2 text-sm text-neutral-400">
                <div className="w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse" />
                <span>All systems operational</span>
              </div>

              <div className="flex items-center gap-4">
                <Link
                  to="/help"
                  className="flex items-center gap-1.5 text-sm text-neutral-400 hover:text-foreground transition-smooth"
                >
                  <MessageSquare className="w-3.5 h-3.5" />
                  <span>Help</span>
                </Link>
                <a
                  href="mailto:hello@nexabot.ai"
                  className="flex items-center gap-1.5 text-sm text-neutral-400 hover:text-foreground transition-smooth"
                >
                  <Mail className="w-3.5 h-3.5" />
                  <span>Contact</span>
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
