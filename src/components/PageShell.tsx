import { ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { LogoIcon, LogoText } from "@/components/ui/logo";

interface PageShellProps {
  title: string;
  eyebrow?: string;
  description?: string;
  children: React.ReactNode;
}

const PageShell = ({ title, eyebrow, description, children }: PageShellProps) => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b border-border/40 bg-white/90 backdrop-blur-lg">
        <div className="container mx-auto px-6 h-16 flex items-center justify-between">
          <Button
            variant="ghost"
            onClick={() => navigate("/")}
            className="text-neutral-500 hover:text-foreground"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Home
          </Button>
          <button
            className="flex items-center gap-2.5"
            onClick={() => navigate("/")}
          >
            <LogoIcon className="w-8 h-8" />
            <LogoText className="text-lg" />
          </button>
        </div>
      </header>

      <main className="container mx-auto px-6 py-12 max-w-5xl">
        <div className="mb-10 max-w-3xl">
          {eyebrow && (
            <div className="text-sm font-semibold text-primary mb-3">
              {eyebrow}
            </div>
          )}
          <h1 className="text-4xl lg:text-5xl font-bold tracking-tight text-foreground">
            {title}
          </h1>
          {description && (
            <p className="mt-4 text-lg text-neutral-500 leading-relaxed">
              {description}
            </p>
          )}
        </div>
        {children}
      </main>
    </div>
  );
};

export default PageShell;

