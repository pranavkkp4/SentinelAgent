import { useEffect, useState } from 'react';
import { Shield, Play } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { Toaster } from '@/components/ui/sonner';

// Sections
import HeroSection from './sections/HeroSection';
import HowItWorksSection from './sections/HowItWorksSection';
import AttackDemoSection from './sections/AttackDemoSection';
import MetricsDashboard from './sections/MetricsDashboard';
import TechStackSection from './sections/TechStackSection';
import FooterSection from './sections/FooterSection';

function App() {
  const [scrollY, setScrollY] = useState(0);

  useEffect(() => {
    const handleScroll = () => setScrollY(window.scrollY);
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <div className="min-h-screen bg-[#0F172A] text-[#F8FAFC]">
      <Toaster position="top-right" theme="dark" />
      
      {/* Navigation */}
      <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrollY > 50 ? 'bg-[#0F172A]/90 backdrop-blur-lg border-b border-[#1E293B]' : 'bg-transparent'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#38BDF8] to-[#8B5CF6] flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <span className="text-xl font-bold">SentinelAgent</span>
            </div>
            <div className="hidden md:flex items-center gap-6">
              <a href="#how-it-works" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors">How It Works</a>
              <a href="#attack-demo" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors">Attack Demo</a>
              <a href="#metrics" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors">Metrics</a>
              <a href="#tech-stack" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors">Tech Stack</a>
              <Button 
                className="bg-gradient-to-r from-[#38BDF8] to-[#8B5CF6] hover:opacity-90 text-white"
                onClick={() => toast.info('Interactive demo coming soon!')}
              >
                <Play className="w-4 h-4 mr-2" />
                Try Demo
              </Button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main>
        <HeroSection />
        <HowItWorksSection />
        <AttackDemoSection />
        <MetricsDashboard />
        <TechStackSection />
        <FooterSection />
      </main>
    </div>
  );
}

export default App;
