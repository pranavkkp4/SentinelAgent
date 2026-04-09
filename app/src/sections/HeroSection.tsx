import { Shield, Lock, Eye, ArrowRight, Activity } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

const HeroSection = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center pt-16 overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[#38BDF8]/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[#8B5CF6]/10 rounded-full blur-3xl" />
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiMzOENERjgiIGZpbGwtb3BhY2l0eT0iMC4wMyI+PGNpcmNsZSBjeD0iMzAiIGN5PSIzMCIgcj0iMSIvPjwvZz48L2c+PC9zdmc+')] opacity-30" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="text-center">
          {/* Badge */}
          <Badge className="mb-6 px-4 py-2 bg-[#1E293B] border border-[#38BDF8]/30 text-[#38BDF8] hover:bg-[#1E293B]">
            <Activity className="w-4 h-4 mr-2" />
            ML-Based Defense System
          </Badge>

          {/* Main Title */}
          <h1 className="text-5xl md:text-7xl font-bold mb-6 leading-tight">
            <span className="text-[#F8FAFC]">Sentinel</span>
            <span className="text-gradient">Agent</span>
          </h1>
          
          <p className="text-2xl md:text-3xl text-[#94A3B8] mb-8 max-w-3xl mx-auto">
            Securing AI Agents from{' '}
            <span className="text-[#38BDF8] font-semibold">Prompt Injection</span>
            {' '}and{' '}
            <span className="text-[#8B5CF6] font-semibold">Data Exfiltration</span>
          </p>

          {/* Description */}
          <p className="text-lg text-[#64748B] mb-12 max-w-2xl mx-auto">
            A defense-in-depth architecture that treats the LLM as an untrusted reasoning component, 
            introducing ML-based security middleware across three enforcement boundaries: 
            retrieval-time injection detection, tool-call risk classification, and response-level exfiltration detection.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-16">
            <Button 
              size="lg" 
              className="bg-gradient-to-r from-[#38BDF8] to-[#22D3EE] hover:opacity-90 text-white px-8 py-6 text-lg glow-primary"
              onClick={() => document.getElementById('attack-demo')?.scrollIntoView({ behavior: 'smooth' })}
            >
              See Attack Demo
              <ArrowRight className="w-5 h-5 ml-2" />
            </Button>
            <Button 
              size="lg" 
              variant="outline" 
              className="border-[#334155] text-[#F8FAFC] hover:bg-[#1E293B] px-8 py-6 text-lg"
              onClick={() => document.getElementById('how-it-works')?.scrollIntoView({ behavior: 'smooth' })}
            >
              Learn More
            </Button>
          </div>

          {/* Architecture Diagram */}
          <div className="relative max-w-4xl mx-auto">
            <div className="card-surface-alt p-8">
              <h3 className="text-lg font-semibold mb-6 text-[#94A3B8]">Defense-in-Depth Architecture</h3>
              
              {/* Architecture Flow */}
              <div className="flex flex-col md:flex-row items-center justify-center gap-4">
                {/* User Query */}
                <div className="flex flex-col items-center">
                  <div className="w-16 h-16 rounded-xl bg-[#1E293B] border border-[#38BDF8]/30 flex items-center justify-center mb-2">
                    <span className="text-2xl">👤</span>
                  </div>
                  <span className="text-sm text-[#94A3B8]">User Query</span>
                </div>

                <ArrowRight className="w-6 h-6 text-[#38BDF8] hidden md:block" />

                {/* Agent Orchestrator */}
                <div className="flex flex-col items-center">
                  <div className="w-20 h-20 rounded-xl bg-gradient-to-br from-[#38BDF8]/20 to-[#8B5CF6]/20 border border-[#38BDF8]/50 flex items-center justify-center mb-2">
                    <Shield className="w-10 h-10 text-[#38BDF8]" />
                  </div>
                  <span className="text-sm text-[#94A3B8]">Agent Orchestrator</span>
                </div>

                <ArrowRight className="w-6 h-6 text-[#38BDF8] hidden md:block" />

                {/* Security Middleware */}
                <div className="flex flex-col items-center">
                  <div className="w-24 h-24 rounded-xl bg-gradient-to-br from-[#8B5CF6]/30 to-[#EF4444]/20 border-2 border-[#8B5CF6] flex flex-col items-center justify-center mb-2 relative">
                    <Lock className="w-8 h-8 text-[#8B5CF6] mb-1" />
                    <span className="text-xs text-[#8B5CF6] font-semibold">SECURITY</span>
                    <div className="absolute -top-2 -right-2 w-4 h-4 bg-[#10B981] rounded-full animate-pulse" />
                  </div>
                  <span className="text-sm text-[#94A3B8]">3-Layer Defense</span>
                </div>

                <ArrowRight className="w-6 h-6 text-[#38BDF8] hidden md:block" />

                {/* Safe Response */}
                <div className="flex flex-col items-center">
                  <div className="w-16 h-16 rounded-xl bg-[#10B981]/20 border border-[#10B981]/50 flex items-center justify-center mb-2">
                    <Eye className="w-8 h-8 text-[#10B981]" />
                  </div>
                  <span className="text-sm text-[#94A3B8]">Safe Response</span>
                </div>
              </div>

              {/* Security Layers Detail */}
              <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-[#0F172A] rounded-lg p-4 border border-[#38BDF8]/20">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-3 h-3 rounded-full bg-[#38BDF8]" />
                    <span className="text-sm font-medium text-[#38BDF8]">Layer 1</span>
                  </div>
                  <p className="text-xs text-[#94A3B8]">Injection Detection</p>
                </div>
                <div className="bg-[#0F172A] rounded-lg p-4 border border-[#8B5CF6]/20">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-3 h-3 rounded-full bg-[#8B5CF6]" />
                    <span className="text-sm font-medium text-[#8B5CF6]">Layer 2</span>
                  </div>
                  <p className="text-xs text-[#94A3B8]">Tool Risk Classification</p>
                </div>
                <div className="bg-[#0F172A] rounded-lg p-4 border border-[#10B981]/20">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-3 h-3 rounded-full bg-[#10B981]" />
                    <span className="text-sm font-medium text-[#10B981]">Layer 3</span>
                  </div>
                  <p className="text-xs text-[#94A3B8]">Exfiltration Detection</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Scroll Indicator */}
      <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 animate-bounce">
        <div className="w-6 h-10 rounded-full border-2 border-[#38BDF8]/30 flex justify-center pt-2">
          <div className="w-1.5 h-3 bg-[#38BDF8] rounded-full animate-pulse" />
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
