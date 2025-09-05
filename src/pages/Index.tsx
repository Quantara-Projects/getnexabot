import Hero from '@/components/Hero';
import ProblemSection from '@/components/ProblemSection';
import SolutionSection from '@/components/SolutionSection';
import FeaturesSection from '@/components/FeaturesSection';
import IntegrationsSection from '@/components/IntegrationsSection';
import CompanySections from '@/components/CompanySections';
import HowItWorks from '@/components/HowItWorks';
import DemoSection from '@/components/DemoSection';
import PricingSection from '@/components/PricingSection';
import Footer from '@/components/Footer';

const Index = () => {
  return (
    <div className="min-h-screen">
      <Hero />
      <ProblemSection />
      <SolutionSection />
      <FeaturesSection />
      <HowItWorks />
      <DemoSection />
      <IntegrationsSection />
      <CompanySections />
      <QuantaraSection />
      <PricingSection />
      <Footer />
    </div>
  );
};

export default Index;
