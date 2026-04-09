import { Search, Brain, Wrench, Shield, ArrowRight, CheckCircle } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

const HowItWorksSection = () => {
  const pipelineSteps = [
    {
      icon: Search,
      title: 'Retrieval',
      description: 'Documents are retrieved from vector store and screened for injection attempts',
      color: '#38BDF8',
      details: ['FAISS vector search', 'Semantic similarity', 'Content chunking']
    },
    {
      icon: Brain,
      title: 'LLM',
      description: 'Language model processes filtered context to generate response',
      color: '#8B5CF6',
      details: ['Context construction', 'Reasoning', 'Response generation']
    },
    {
      icon: Wrench,
      title: 'Tools',
      description: 'Tool calls are evaluated for risk before execution',
      color: '#F59E0B',
      details: ['Risk classification', 'Policy enforcement', 'Action execution']
    },
    {
      icon: Shield,
      title: 'Security Middleware',
      description: 'Three-layer defense system protecting at every boundary',
      color: '#10B981',
      details: ['Injection detection', 'Tool-call gating', 'Exfiltration scanning']
    }
  ];

  const securityLayers = [
    {
      name: 'Injection Detection',
      description: 'Screens retrieved content for prompt injection attempts using pattern matching and statistical analysis',
      status: 'active',
      capabilities: [
        'Pattern-based detection',
        'Statistical feature analysis',
        'Entropy calculation',
        'Content sanitization'
      ]
    },
    {
      name: 'Tool-Call Risk Classification',
      description: 'Evaluates proposed tool calls for policy compliance and potential risks',
      status: 'active',
      capabilities: [
        'Tool name risk scoring',
        'Argument analysis',
        'Domain policy checking',
        'Context-aware assessment'
      ]
    },
    {
      name: 'Exfiltration Detection',
      description: 'Scans outputs for sensitive data leakage including canary tokens and API keys',
      status: 'active',
      capabilities: [
        'Canary token detection',
        'API key pattern matching',
        'Encoded data detection',
        'Output sanitization'
      ]
    }
  ];

  return (
    <section id="how-it-works" className="py-24 relative">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-[#0F172A] via-[#111827] to-[#0F172A]" />
      
      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <Badge className="mb-4 px-4 py-2 bg-[#1E293B] border border-[#38BDF8]/30 text-[#38BDF8]">
            Architecture
          </Badge>
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            How It <span className="text-gradient">Works</span>
          </h2>
          <p className="text-lg text-[#94A3B8] max-w-2xl mx-auto">
            SentinelAgent implements a defense-in-depth architecture with security checks at every stage of the agent pipeline
          </p>
        </div>

        {/* Pipeline Visualization */}
        <div className="mb-20">
          <h3 className="text-xl font-semibold text-center mb-8 text-[#94A3B8]">Agent Pipeline Flow</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {pipelineSteps.map((step, index) => (
              <div key={step.title} className="relative">
                <Card className="bg-[#111827] border-[#1E293B] h-full hover:border-[#38BDF8]/50 transition-all duration-300">
                  <CardContent className="p-6">
                    <div 
                      className="w-14 h-14 rounded-xl flex items-center justify-center mb-4"
                      style={{ backgroundColor: `${step.color}20`, border: `1px solid ${step.color}40` }}
                    >
                      <step.icon className="w-7 h-7" style={{ color: step.color }} />
                    </div>
                    <h4 className="text-lg font-semibold mb-2 text-[#F8FAFC]">{step.title}</h4>
                    <p className="text-sm text-[#94A3B8] mb-4">{step.description}</p>
                    <ul className="space-y-1">
                      {step.details.map((detail, i) => (
                        <li key={i} className="text-xs text-[#64748B] flex items-center gap-2">
                          <div className="w-1 h-1 rounded-full" style={{ backgroundColor: step.color }} />
                          {detail}
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
                
                {/* Arrow connector */}
                {index < pipelineSteps.length - 1 && (
                  <div className="hidden lg:flex absolute top-1/2 -right-3 transform -translate-y-1/2 z-10">
                    <ArrowRight className="w-6 h-6 text-[#38BDF8]" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Security Layers Detail */}
        <div>
          <h3 className="text-xl font-semibold text-center mb-8 text-[#94A3B8]">Security Middleware Layers</h3>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {securityLayers.map((layer, index) => (
              <Card key={layer.name} className="bg-[#111827] border-[#1E293B] overflow-hidden">
                <div className="h-1 bg-gradient-to-r from-[#38BDF8] via-[#8B5CF6] to-[#10B981]" 
                  style={{ 
                    background: index === 0 ? '#38BDF8' : index === 1 ? '#8B5CF6' : '#10B981' 
                  }} 
                />
                <CardContent className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-lg font-semibold text-[#F8FAFC]">{layer.name}</h4>
                    <Badge className="bg-[#10B981]/20 text-[#10B981] border-[#10B981]/30">
                      <CheckCircle className="w-3 h-3 mr-1" />
                      Active
                    </Badge>
                  </div>
                  <p className="text-sm text-[#94A3B8] mb-4">{layer.description}</p>
                  
                  <div className="space-y-2">
                    <span className="text-xs font-medium text-[#64748B] uppercase tracking-wider">Capabilities</span>
                    {layer.capabilities.map((cap, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm text-[#94A3B8]">
                        <div 
                          className="w-1.5 h-1.5 rounded-full"
                          style={{ 
                            backgroundColor: index === 0 ? '#38BDF8' : index === 1 ? '#8B5CF6' : '#10B981' 
                          }}
                        />
                        {cap}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Data Flow Diagram */}
        <div className="mt-16">
          <h3 className="text-xl font-semibold text-center mb-8 text-[#94A3B8]">Data Flow with Security Checks</h3>
          
          <div className="card-surface-alt p-8">
            <div className="flex flex-col items-center space-y-6">
              {/* Input */}
              <div className="w-full max-w-md">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-sm text-[#64748B]">User Input</span>
                </div>
                <div className="bg-[#0F172A] rounded-lg p-4 border border-[#334155]">
                  <code className="text-sm text-[#94A3B8]">"Search for company policies"</code>
                </div>
              </div>

              <ArrowRight className="w-6 h-6 text-[#38BDF8] rotate-90" />

              {/* Security Check 1 */}
              <div className="w-full max-w-md">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-3 h-3 rounded-full bg-[#38BDF8]" />
                  <span className="text-sm text-[#38BDF8]">Check 1: Injection Detection</span>
                  <CheckCircle className="w-4 h-4 text-[#10B981]" />
                </div>
                <div className="bg-[#0F172A] rounded-lg p-4 border border-[#38BDF8]/30">
                  <p className="text-xs text-[#94A3B8]">Content screened: <span className="text-[#10B981]">BENIGN</span></p>
                  <p className="text-xs text-[#64748B] mt-1">Confidence: 0.95</p>
                </div>
              </div>

              <ArrowRight className="w-6 h-6 text-[#38BDF8] rotate-90" />

              {/* LLM Processing */}
              <div className="w-full max-w-md">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-sm text-[#64748B]">LLM Processing</span>
                </div>
                <div className="bg-[#0F172A] rounded-lg p-4 border border-[#8B5CF6]/30">
                  <p className="text-xs text-[#94A3B8]">Retrieving relevant documents...</p>
                  <p className="text-xs text-[#94A3B8]">Generating response...</p>
                </div>
              </div>

              <ArrowRight className="w-6 h-6 text-[#38BDF8] rotate-90" />

              {/* Security Check 2 */}
              <div className="w-full max-w-md">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-3 h-3 rounded-full bg-[#8B5CF6]" />
                  <span className="text-sm text-[#8B5CF6]">Check 2: Tool Risk Classification</span>
                  <CheckCircle className="w-4 h-4 text-[#10B981]" />
                </div>
                <div className="bg-[#0F172A] rounded-lg p-4 border border-[#8B5CF6]/30">
                  <p className="text-xs text-[#94A3B8]">Tool call evaluated: <span className="text-[#10B981]">ALLOWED</span></p>
                  <p className="text-xs text-[#64748B] mt-1">Risk score: 0.15 (LOW)</p>
                </div>
              </div>

              <ArrowRight className="w-6 h-6 text-[#38BDF8] rotate-90" />

              {/* Security Check 3 */}
              <div className="w-full max-w-md">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-3 h-3 rounded-full bg-[#10B981]" />
                  <span className="text-sm text-[#10B981]">Check 3: Exfiltration Detection</span>
                  <CheckCircle className="w-4 h-4 text-[#10B981]" />
                </div>
                <div className="bg-[#0F172A] rounded-lg p-4 border border-[#10B981]/30">
                  <p className="text-xs text-[#94A3B8]">Output scanned: <span className="text-[#10B981]">NO LEAKAGE</span></p>
                  <p className="text-xs text-[#64748B] mt-1">Findings: 0</p>
                </div>
              </div>

              <ArrowRight className="w-6 h-6 text-[#38BDF8] rotate-90" />

              {/* Output */}
              <div className="w-full max-w-md">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-sm text-[#64748B]">Safe Output</span>
                </div>
                <div className="bg-[#10B981]/10 rounded-lg p-4 border border-[#10B981]/30">
                  <p className="text-sm text-[#F8FAFC]">"Here are the company policies I found..."</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HowItWorksSection;
