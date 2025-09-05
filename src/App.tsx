import { useEffect, useState } from "react";
import LoadingScreen from "./components/LoadingScreen";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import About from "./pages/About";
import Blog from "./pages/Blog";
import Contact from "./pages/Contact";
import PrivacyPolicy from "./pages/PrivacyPolicy";
import Terms from "./pages/Terms";
import Settings from "./pages/Settings";
import Signup from "./pages/Signup";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import NotFound from "./pages/NotFound";
import CookiePolicy from "./pages/CookiePolicy";
import GDPR from "./pages/GDPR";
import HelpCenter from "./pages/HelpCenter";
import ApiDocs from "./pages/ApiDocs";
import Status from "./pages/Status";
import Community from "./pages/Community";
import VerifyEmail from "./pages/VerifyEmail";
import ErrorOverlay from "./components/ErrorOverlay";

const queryClient = new QueryClient();

const App = () => {
  const [verified, setVerified] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem("humanVerified") === "1";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      if (verified) sessionStorage.setItem("humanVerified", "1");
    } catch {}
  }, [verified]);

  if (!verified) {
    return (
      <LoadingScreen
        onVerify={() => setVerified(true)}
        title="Loading..."
        subtitle="Preparing your experience"
        selectedContent={<img src="https://cdn.builder.io/api/v1/image/assets%2Ff7636dbc154444f9897eafaf4c70d8a5%2Fcbd065bb4fda4ac99cd7d9b6e002e947?format=webp&width=800" alt="selected" className="w-20 h-20 object-contain" />}
      />
    );
  }

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <ErrorOverlay />
        <Toaster />
        <Sonner />
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/about" element={<About />} />
          <Route path="/blog" element={<Blog />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/privacy" element={<PrivacyPolicy />} />
          <Route path="/terms" element={<Terms />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/verify" element={<VerifyEmail />} />
          <Route path="/cookies" element={<CookiePolicy />} />
          <Route path="/gdpr" element={<GDPR />} />
          <Route path="/help" element={<HelpCenter />} />
          <Route path="/api" element={<ApiDocs />} />
          <Route path="/status" element={<Status />} />
          <Route path="/community" element={<Community />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
