import { Server, Cpu, Container, Database, Code, Terminal, GitBranch, Layers } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

const TechStackSection = () => {
  const techCategories = [
    {
      name: 'Backend',
      icon: Server,
      color: '#38BDF8',
      technologies: [
        { name: 'Python', description: 'Core language for ML and security logic', version: '3.11+' },
        { name: 'FastAPI', description: 'High-performance async web framework', version: '0.109+' },
        { name: 'Pydantic', description: 'Data validation and serialization', version: '2.5+' },
        { name: 'Uvicorn', description: 'ASGI server for production deployment', version: '0.27+' }
      ]
    },
    {
      name: 'Machine Learning',
      icon: Cpu,
      color: '#8B5CF6',
      technologies: [
        { name: 'Transformers', description: 'State-of-the-art NLP models', version: '4.36+' },
        { name: 'PyTorch', description: 'Deep learning framework', version: '2.2+' },
        { name: 'scikit-learn', description: 'Classical ML algorithms', version: '1.4+' },
        { name: 'NumPy', description: 'Numerical computing', version: '1.26+' }
      ]
    },
    {
      name: 'Vector Search',
      icon: Database,
      color: '#10B981',
      technologies: [
        { name: 'FAISS', description: 'Efficient similarity search', version: '1.7+' },
        { name: 'Sentence-Transformers', description: 'Text embeddings', version: '2.2+' },
        { name: 'NumPy', description: 'Vector operations', version: '1.26+' }
      ]
    },
    {
      name: 'Infrastructure',
      icon: Container,
      color: '#F59E0B',
      technologies: [
        { name: 'Docker', description: 'Containerization', version: '24+' },
        { name: 'Docker Compose', description: 'Multi-container orchestration', version: '2.23+' },
        { name: 'Redis', description: 'Caching layer (optional)', version: '7+' }
      ]
    }
  ];

  const architectureLayers = [
    {
      name: 'API Layer',
      description: 'RESTful endpoints for queries, attacks, and metrics',
      icon: Code,
      color: '#38BDF8'
    },
    {
      name: 'Agent Orchestrator',
      description: 'Plan-Act-Observe loop with step limiting',
      icon: Terminal,
      color: '#8B5CF6'
    },
    {
      name: 'Security Middleware',
      description: '3-layer defense: injection, tool risk, exfiltration',
      icon: Layers,
      color: '#EF4444'
    },
    {
      name: 'Retrieval Subsystem',
      description: 'FAISS-based RAG with document chunking',
      icon: Database,
      color: '#10B981'
    },
    {
      name: 'Tooling Layer',
      description: 'Controlled action interfaces with logging',
      icon: GitBranch,
      color: '#F59E0B'
    }
  ];

  return (
    <section id="tech-stack" className="py-24 relative">
      {/* Background */}
      <div className="absolute inset-0 bg-[#0F172A]" />
      <div className="absolute top-0 left-1/2 transform -translate-x-1/2 w-full h-px bg-gradient-to-r from-transparent via-[#38BDF8]/30 to-transparent" />
      
      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <Badge className="mb-4 px-4 py-2 bg-[#1E293B] border border-[#38BDF8]/30 text-[#38BDF8]">
            <Code className="w-4 h-4 mr-2" />
            Technology Stack
          </Badge>
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Built with Modern <span className="text-gradient">Technologies</span>
          </h2>
          <p className="text-lg text-[#94A3B8] max-w-2xl mx-auto">
            SentinelAgent leverages cutting-edge tools and frameworks for robust, scalable security
          </p>
        </div>

        {/* Tech Categories */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-16">
          {techCategories.map((category) => (
            <Card key={category.name} className="bg-[#111827] border-[#1E293B] overflow-hidden">
              <div 
                className="h-1"
                style={{ backgroundColor: category.color }}
              />
              <CardContent className="p-6">
                <div className="flex items-center gap-3 mb-6">
                  <div 
                    className="w-12 h-12 rounded-xl flex items-center justify-center"
                    style={{ backgroundColor: `${category.color}20` }}
                  >
                    <category.icon className="w-6 h-6" style={{ color: category.color }} />
                  </div>
                  <h3 className="text-xl font-semibold text-[#F8FAFC]">{category.name}</h3>
                </div>

                <div className="space-y-4">
                  {category.technologies.map((tech) => (
                    <div key={tech.name} className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-[#F8FAFC]">{tech.name}</span>
                          <Badge 
                            variant="outline" 
                            className="text-xs"
                            style={{ borderColor: `${category.color}40`, color: category.color }}
                          >
                            {tech.version}
                          </Badge>
                        </div>
                        <p className="text-sm text-[#64748B]">{tech.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Architecture Layers */}
        <div className="mb-16">
          <h3 className="text-xl font-semibold text-center mb-8 text-[#94A3B8]">System Architecture</h3>
          
          <div className="relative">
            {/* Connection Line */}
            <div className="absolute left-8 top-8 bottom-8 w-0.5 bg-gradient-to-b from-[#38BDF8] via-[#8B5CF6] to-[#10B981] hidden md:block" />
            
            <div className="space-y-4">
              {architectureLayers.map((layer, index) => (
                <Card key={layer.name} className="bg-[#111827] border-[#1E293B] md:ml-16">
                  <CardContent className="p-4 flex items-center gap-4">
                    <div 
                      className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${layer.color}20`, border: `1px solid ${layer.color}40` }}
                    >
                      <layer.icon className="w-6 h-6" style={{ color: layer.color }} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-1">
                        <h4 className="font-semibold text-[#F8FAFC]">{layer.name}</h4>
                        <Badge 
                          variant="outline" 
                          className="text-xs"
                          style={{ borderColor: `${layer.color}40`, color: layer.color }}
                        >
                          Layer {index + 1}
                        </Badge>
                      </div>
                      <p className="text-sm text-[#94A3B8]">{layer.description}</p>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>

        {/* GitHub & Paper Links */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="bg-gradient-to-br from-[#111827] to-[#1E293B] border-[#334155] hover:border-[#38BDF8]/50 transition-all cursor-pointer group">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-xl bg-[#333] flex items-center justify-center group-hover:scale-110 transition-transform">
                  <svg className="w-8 h-8 text-white" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold text-[#F8FAFC] group-hover:text-[#38BDF8] transition-colors">GitHub Repository</h4>
                  <p className="text-sm text-[#94A3B8]">View source code, documentation, and contribute</p>
                  <code className="text-xs text-[#64748B] mt-1 block">github.com/sentinel-agent/sentinel-agent</code>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-br from-[#111827] to-[#1E293B] border-[#334155] hover:border-[#8B5CF6]/50 transition-all cursor-pointer group">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-xl bg-[#8B5CF6]/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                  <svg className="w-8 h-8 text-[#8B5CF6]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold text-[#F8FAFC] group-hover:text-[#8B5CF6] transition-colors">Research Paper</h4>
                  <p className="text-sm text-[#94A3B8]">Read the full technical paper and evaluation</p>
                  <code className="text-xs text-[#64748B] mt-1 block">arxiv.org/abs/sentinel-agent</code>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
};

export default TechStackSection;
