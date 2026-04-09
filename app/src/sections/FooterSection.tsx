import { Shield, Github, FileText, Twitter, Linkedin } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

const FooterSection = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="relative bg-[#0F172A] border-t border-[#1E293B]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          {/* Brand */}
          <div className="md:col-span-2">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#38BDF8] to-[#8B5CF6] flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <span className="text-xl font-bold text-[#F8FAFC]">SentinelAgent</span>
            </div>
            <p className="text-[#94A3B8] mb-4 max-w-md">
              ML-Based Defense Against Prompt Injection and Data Exfiltration in Tool-Using LLM Agents. 
              Protecting AI systems with defense-in-depth security middleware.
            </p>
            <div className="flex gap-4">
              <a 
                href="#" 
                className="w-10 h-10 rounded-lg bg-[#1E293B] flex items-center justify-center text-[#94A3B8] hover:text-[#38BDF8] hover:bg-[#38BDF8]/10 transition-all"
              >
                <Github className="w-5 h-5" />
              </a>
              <a 
                href="#" 
                className="w-10 h-10 rounded-lg bg-[#1E293B] flex items-center justify-center text-[#94A3B8] hover:text-[#8B5CF6] hover:bg-[#8B5CF6]/10 transition-all"
              >
                <FileText className="w-5 h-5" />
              </a>
              <a 
                href="#" 
                className="w-10 h-10 rounded-lg bg-[#1E293B] flex items-center justify-center text-[#94A3B8] hover:text-[#38BDF8] hover:bg-[#38BDF8]/10 transition-all"
              >
                <Twitter className="w-5 h-5" />
              </a>
              <a 
                href="#" 
                className="w-10 h-10 rounded-lg bg-[#1E293B] flex items-center justify-center text-[#94A3B8] hover:text-[#38BDF8] hover:bg-[#38BDF8]/10 transition-all"
              >
                <Linkedin className="w-5 h-5" />
              </a>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="font-semibold text-[#F8FAFC] mb-4">Quick Links</h4>
            <ul className="space-y-2">
              <li>
                <a href="#how-it-works" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors text-sm">
                  How It Works
                </a>
              </li>
              <li>
                <a href="#attack-demo" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors text-sm">
                  Attack Demo
                </a>
              </li>
              <li>
                <a href="#metrics" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors text-sm">
                  Metrics Dashboard
                </a>
              </li>
              <li>
                <a href="#tech-stack" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors text-sm">
                  Tech Stack
                </a>
              </li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="font-semibold text-[#F8FAFC] mb-4">Resources</h4>
            <ul className="space-y-2">
              <li>
                <a href="#" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors text-sm">
                  Documentation
                </a>
              </li>
              <li>
                <a href="#" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors text-sm">
                  API Reference
                </a>
              </li>
              <li>
                <a href="#" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors text-sm">
                  Research Paper
                </a>
              </li>
              <li>
                <a href="#" className="text-[#94A3B8] hover:text-[#38BDF8] transition-colors text-sm">
                  GitHub Repository
                </a>
              </li>
            </ul>
          </div>
        </div>

        <Separator className="bg-[#1E293B] mb-8" />

        {/* Bottom Bar */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-[#64748B]">
            © {currentYear} SentinelAgent. All rights reserved.
          </p>
          <div className="flex items-center gap-6">
            <a href="#" className="text-sm text-[#64748B] hover:text-[#94A3B8] transition-colors">
              Privacy Policy
            </a>
            <a href="#" className="text-sm text-[#64748B] hover:text-[#94A3B8] transition-colors">
              Terms of Service
            </a>
            <a href="#" className="text-sm text-[#64748B] hover:text-[#94A3B8] transition-colors">
              License
            </a>
          </div>
        </div>

        {/* Attribution */}
        <div className="mt-8 text-center">
          <p className="text-xs text-[#475569]">
            Developed by Pranav Kumar Kaliaperumal at University of Colorado Denver
          </p>
          <p className="text-xs text-[#475569] mt-1">
            CSCI 5742: Cybersecurity Programming • Spring 2026
          </p>
        </div>
      </div>
    </footer>
  );
};

export default FooterSection;
