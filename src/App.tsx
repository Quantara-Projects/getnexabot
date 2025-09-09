import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
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

const LoadingScreen = ({ onFinish }: any) => {
  const [progressDone, setProgressDone] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setProgressDone(true);
      setTimeout(() => {
        onFinish();
      }, 3000); // wait 3 seconds before showing main page
    }, 3000); // progress duration (bar fills up in 3s)

    return () => clearTimeout(timer);
  }, [onFinish]);

  return (
    <motion.div
      initial={{ opacity: 1 }}
      animate={{ opacity: progressDone ? 0 : 1 }}
      transition={{ duration: 1.5, ease: "easeInOut" }}
      className="flex h-screen w-full flex-col items-center justify-center 
                 bg-gradient-to-b from-indigo-50 to-white text-gray-900"
    >
      <div className="flex flex-col items-center text-center space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-wide text-gray-800">
            NexaBot
          </h1>
          <p className="mt-2 text-gray-500 text-sm">
            Preparing your experience
          </p>
        </div>

        <motion.div
          className="w-64 h-2 bg-gray-200 rounded-full overflow-hidden"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
        >
          <motion.div
            className="h-full bg-gradient-to-r from-indigo-500 via-purple-500 to-indigo-500"
            initial={{ width: 0 }}
            animate={{ width: "100%" }}
            transition={{ duration: 3, ease: "easeInOut" }}
          />
        </motion.div>

        <p className="mt-6 text-sm text-indigo-600 animate-pulse">
          NexaBot is making the website ready for you!
        </p>
      </div>
    </motion.div>
  );
};

const App = () => {
  const [loadingDone, setLoadingDone] = useState(false);

  if (!loadingDone) {
    return <LoadingScreen onFinish={() => setLoadingDone(true)} />;
  }

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <ErrorOverlay />
        <Toaster />
        <Sonner />
        <AnimatePresence mode="wait">
          <motion.div
            key="main"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1.5, ease: "easeInOut" }}
          >
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
          </motion.div>
        </AnimatePresence>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
