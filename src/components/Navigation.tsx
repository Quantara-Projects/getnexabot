import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Menu, X } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { LogoIcon, LogoText } from "@/components/ui/logo";

const Navigation = () => {
  const navigate = useNavigate();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const navLinks = [
    { name: "Features", href: "#features" },
    { name: "How It Works", href: "#how-it-works" },
    { name: "Demo", href: "#demo" },
    { name: "Pricing", href: "#pricing" },
  ];

  return (
    <nav
      className={`fixed top-0 w-full z-50 transition-all duration-300 ${
        scrolled
          ? "bg-white/90 backdrop-blur-lg border-b border-border/50 shadow-sm"
          : "bg-transparent"
      }`}
    >
      <div className="container mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div
            className="flex items-center gap-3 cursor-pointer group"
            onClick={() => navigate("/")}
          >
            <LogoIcon className="w-9 h-9 group-hover:scale-105 transition-transform" />
            <LogoText className="text-xl" />
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center gap-8">
            {navLinks.map((link) => (
              <a
                key={link.name}
                href={link.href}
                className="text-neutral-500 hover:text-foreground transition-smooth font-medium text-sm"
              >
                {link.name}
              </a>
            ))}
          </div>

          {/* CTA Buttons */}
          <div className="hidden md:flex items-center gap-3">
            <Button
              variant="ghost"
              className="font-medium text-neutral-600 hover:text-foreground"
              onClick={() => navigate("/login")}
            >
              Sign In
            </Button>
            <Button
              className="h-11 px-5 rounded-lg bg-primary text-white hover:bg-primary/90 shadow-sm hover:shadow-md active:scale-[0.98] transition-all font-semibold"
              onClick={() => navigate("/signup")}
            >
              Get Started Free
            </Button>
          </div>

          {/* Mobile Menu Button */}
          <button
            className="md:hidden p-2 rounded-lg hover:bg-secondary transition-smooth"
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            aria-label="Toggle menu"
          >
            {isMenuOpen ? (
              <X className="w-5 h-5" />
            ) : (
              <Menu className="w-5 h-5" />
            )}
          </button>
        </div>

        {/* Mobile Menu */}
        {isMenuOpen && (
          <div className="md:hidden py-4 border-t border-border/50 animate-fade-up">
            <div className="flex flex-col gap-2">
              {navLinks.map((link) => (
                <a
                  key={link.name}
                  href={link.href}
                  className="text-neutral-600 hover:text-foreground transition-smooth font-medium py-2.5 px-3 rounded-lg hover:bg-secondary"
                  onClick={() => setIsMenuOpen(false)}
                >
                  {link.name}
                </a>
              ))}
              <div className="flex flex-col gap-2 pt-4 border-t border-border/50 mt-2">
                <Button
                  variant="ghost"
                  className="font-medium justify-start text-neutral-600"
                  onClick={() => {
                    navigate("/login");
                    setIsMenuOpen(false);
                  }}
                >
                  Sign In
                </Button>
                <Button
                  className="bg-primary text-white hover:bg-primary/90 justify-start"
                  onClick={() => {
                    navigate("/signup");
                    setIsMenuOpen(false);
                  }}
                >
                  Get Started Free
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
};

export default Navigation;
