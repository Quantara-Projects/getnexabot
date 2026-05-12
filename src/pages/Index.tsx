import Hero from "@/components/Hero";
import FeaturesSection from "@/components/FeaturesSection";
import IntegrationsSection from "@/components/IntegrationsSection";
import HowItWorks from "@/components/HowItWorks";
import DemoSection from "@/components/DemoSection";
import PricingSection from "@/components/PricingSection";
import Footer from "@/components/Footer";

const Index = () => {
  return (
    <div className="min-h-screen">
      <Hero />
      <FeaturesSection />
      <HowItWorks />
      <DemoSection />
      <IntegrationsSection />
      <PricingSection />
      <Footer />
    </div>
  );
};

export default Index;
