import { useState, useEffect, useCallback } from 'react';
import { TrendingDown, TrendingUp, Activity, Shield, Lock, Eye, BarChart3, RefreshCw } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { api, type DefenseConfigKey, type MetricsResponseData } from '@/services/api';

const defenseOrder: DefenseConfigKey[] = ['no_defense', 'prompt_only', 'rule_based', 'ml_assisted'];

const defenseConfigs: Record<DefenseConfigKey, { name: string; color: string }> = {
  no_defense: { name: 'No Defense', color: '#EF4444' },
  prompt_only: { name: 'Prompt-Only', color: '#F59E0B' },
  rule_based: { name: 'Rule-Based', color: '#38BDF8' },
  ml_assisted: { name: 'ML-Assisted (SentinelAgent)', color: '#10B981' },
};

const MetricsDashboard = () => {
  const [selectedConfig, setSelectedConfig] = useState<DefenseConfigKey>('ml_assisted');
  const [metricsData, setMetricsData] = useState<MetricsResponseData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await api.getMetrics();

      if (response.success && response.data) {
        setMetricsData(response.data);
      } else {
        setMetricsData(null);
        setError(response.error || 'The backend did not return metrics data.');
      }
    } catch (fetchError) {
      setMetricsData(null);
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to load metrics from the backend.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchMetrics();
  }, [fetchMetrics]);

  if (loading) {
    return (
      <section id="metrics" className="py-24 relative">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <Activity className="w-8 h-8 animate-spin mx-auto text-[#38BDF8]" />
          <p className="mt-4 text-[#94A3B8]">Loading metrics from the backend...</p>
        </div>
      </section>
    );
  }

  if (!metricsData) {
    return (
      <section id="metrics" className="py-24 relative">
        <div className="max-w-4xl mx-auto px-4">
          <Card className="bg-[#111827] border border-[#EF4444]/30">
            <CardContent className="p-8 text-center">
              <BarChart3 className="w-10 h-10 mx-auto text-[#EF4444]" />
              <h2 className="mt-4 text-2xl font-bold text-[#F8FAFC]">Metrics unavailable</h2>
              <p className="mt-3 text-[#94A3B8]">
                {error || 'Start the backend API to load live evaluation metrics.'}
              </p>
              <Button
                className="mt-6 bg-[#EF4444] text-white hover:opacity-90"
                onClick={() => void fetchMetrics()}
              >
                <RefreshCw className="w-4 h-4 mr-2" />
                Retry
              </Button>
            </CardContent>
          </Card>
        </div>
      </section>
    );
  }

  const data = metricsData;

  const getSecurityMetric = (
    metric: keyof MetricsResponseData['security_metrics'],
    config: DefenseConfigKey
  ) => data.security_metrics[metric][config];

  const getPerformanceMetric = (
    metric: keyof MetricsResponseData['performance_metrics'],
    config: DefenseConfigKey
  ) => data.performance_metrics[metric][config];

  const metricCards = [
    {
      title: 'Attack Success Rate',
      icon: Shield,
      value: getSecurityMetric('attack_success_rate', selectedConfig),
      target: 0.1,
      unit: '%',
      description: 'Percentage of attacks that succeeded',
      inverse: true,
      color: '#EF4444',
    },
    {
      title: 'Secret Leakage Rate',
      icon: Lock,
      value: getSecurityMetric('secret_leakage_rate', selectedConfig),
      target: 0.1,
      unit: '%',
      description: 'Rate of canary token leakage',
      inverse: true,
      color: '#F59E0B',
    },
    {
      title: 'Unsafe Tool Rate',
      icon: Eye,
      value: getSecurityMetric('unsafe_tool_rate', selectedConfig),
      target: 0.15,
      unit: '%',
      description: 'Rate of unauthorized tool calls',
      inverse: true,
      color: '#8B5CF6',
    },
    {
      title: 'Benign Task Success',
      icon: Activity,
      value: getPerformanceMetric('benign_task_success_rate', selectedConfig),
      target: 0.9,
      unit: '%',
      description: 'Success rate on legitimate tasks',
      inverse: false,
      color: '#10B981',
    },
  ];

  const comparisonData = defenseOrder.map((key) => {
    const config = defenseConfigs[key];

    return {
      name: config.name,
      key,
      color: config.color,
      asr: Math.round(getSecurityMetric('attack_success_rate', key) * 100),
      leakage: Math.round(getSecurityMetric('secret_leakage_rate', key) * 100),
      tool: Math.round(getSecurityMetric('unsafe_tool_rate', key) * 100),
      benign: Math.round(getPerformanceMetric('benign_task_success_rate', key) * 100),
      latency: Math.round(getPerformanceMetric('latency_ms', key)),
    };
  });

  const baselineAttackSuccess = getSecurityMetric('attack_success_rate', 'no_defense') * 100;
  const mlAttackSuccess = getSecurityMetric('attack_success_rate', 'ml_assisted') * 100;
  const attackDrop = baselineAttackSuccess - mlAttackSuccess;
  const baselineLeakage = getSecurityMetric('secret_leakage_rate', 'no_defense') * 100;
  const mlLeakage = getSecurityMetric('secret_leakage_rate', 'ml_assisted') * 100;
  const utilityPreserved = getPerformanceMetric('benign_task_success_rate', 'ml_assisted') * 100;
  const latencyOverhead =
    getPerformanceMetric('latency_ms', 'ml_assisted') -
    getPerformanceMetric('latency_ms', 'no_defense');

  const recommendation =
    data.comparison?.recommendation || 'ML-assisted defense provides the best security-utility trade-off.';

  return (
    <section id="metrics" className="py-24 relative">
      <div className="absolute inset-0 bg-gradient-to-b from-[#0F172A] via-[#111827] to-[#0F172A]" />

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <Badge className="mb-4 px-4 py-2 bg-[#1E293B] border border-[#38BDF8]/30 text-[#38BDF8]">
            <BarChart3 className="w-4 h-4 mr-2" />
            Performance Metrics
          </Badge>
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Security <span className="text-gradient">Metrics</span> Dashboard
          </h2>
          <p className="text-lg text-[#94A3B8] max-w-2xl mx-auto">
            Quantitative evaluation of SentinelAgent's effectiveness across different defense configurations
          </p>
          <p className="mt-3 text-sm text-[#64748B]">
            Last refreshed: {new Date(data.timestamp).toLocaleString()}
          </p>
        </div>

        <div className="flex justify-center mb-12">
          <Tabs value={selectedConfig} onValueChange={(value) => setSelectedConfig(value as DefenseConfigKey)} className="w-full max-w-2xl">
            <TabsList className="grid grid-cols-4 bg-[#111827] border border-[#1E293B]">
              {defenseOrder.map((key) => {
                const config = defenseConfigs[key];

                return (
                  <TabsTrigger
                    key={key}
                    value={key}
                    className="text-xs data-[state=active]:bg-[#1E293B]"
                    style={{
                      color: selectedConfig === key ? config.color : undefined,
                    }}
                  >
                    {config.name}
                  </TabsTrigger>
                );
              })}
            </TabsList>
          </Tabs>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          {metricCards.map((metric) => (
            <Card key={metric.title} className="bg-[#111827] border-[#1E293B] overflow-hidden">
              <div className="h-1" style={{ backgroundColor: metric.color }} />
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <metric.icon className="w-6 h-6" style={{ color: metric.color }} />
                  <Badge
                    variant="outline"
                    className="text-xs"
                    style={{ borderColor: metric.color, color: metric.color }}
                  >
                    {metric.inverse ? 'Lower is better' : 'Higher is better'}
                  </Badge>
                </div>

                <div className="mb-2">
                  <span className="text-3xl font-bold" style={{ color: metric.color }}>
                    {(metric.value * 100).toFixed(0)}
                    {metric.unit}
                  </span>
                </div>

                <p className="text-sm font-medium text-[#F8FAFC] mb-1">{metric.title}</p>
                <p className="text-xs text-[#64748B] mb-4">{metric.description}</p>

                <div className="space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-[#64748B]">Target</span>
                    <span className="text-[#94A3B8]">
                      {(metric.target * 100).toFixed(0)}
                      {metric.unit}
                    </span>
                  </div>
                  <Progress value={metric.value * 100} max={100} className="h-2 bg-[#0F172A]" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <Card className="bg-[#111827] border-[#1E293B] mb-12">
          <CardHeader>
            <CardTitle className="text-[#F8FAFC]">Defense Configuration Comparison</CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            <div className="space-y-6">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-[#94A3B8]">Attack Success Rate (lower is better)</span>
                </div>
                <div className="space-y-2">
                  {comparisonData.map((item) => (
                    <div key={item.name} className="flex items-center gap-4">
                      <span className="text-xs text-[#64748B] w-24">{item.name}</span>
                      <div className="flex-1 h-6 bg-[#0F172A] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${item.asr}%`,
                            backgroundColor: item.color,
                          }}
                        />
                      </div>
                      <span className="text-xs text-[#94A3B8] w-10">{item.asr}%</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-[#94A3B8]">Secret Leakage Rate (lower is better)</span>
                </div>
                <div className="space-y-2">
                  {comparisonData.map((item) => (
                    <div key={item.name} className="flex items-center gap-4">
                      <span className="text-xs text-[#64748B] w-24">{item.name}</span>
                      <div className="flex-1 h-6 bg-[#0F172A] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${item.leakage}%`,
                            backgroundColor: item.color,
                          }}
                        />
                      </div>
                      <span className="text-xs text-[#94A3B8] w-10">{item.leakage}%</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-[#94A3B8]">Benign Task Success Rate (higher is better)</span>
                </div>
                <div className="space-y-2">
                  {comparisonData.map((item) => (
                    <div key={item.name} className="flex items-center gap-4">
                      <span className="text-xs text-[#64748B] w-24">{item.name}</span>
                      <div className="flex-1 h-6 bg-[#0F172A] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${item.benign}%`,
                            backgroundColor: item.color,
                          }}
                        />
                      </div>
                      <span className="text-xs text-[#94A3B8] w-10">{item.benign}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="bg-gradient-to-br from-[#10B981]/10 to-[#059669]/5 border-[#10B981]/30">
            <CardContent className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <TrendingDown className="w-8 h-8 text-[#10B981]" />
                <span className="text-2xl font-bold text-[#10B981]">{attackDrop.toFixed(0)} pts</span>
              </div>
              <h4 className="font-semibold text-[#F8FAFC] mb-2">Attack Reduction</h4>
              <p className="text-sm text-[#94A3B8]">
                Attack success drops from {baselineAttackSuccess.toFixed(0)}% with no defense to {mlAttackSuccess.toFixed(0)}%
                with ML-assisted detection, while leakage falls from {baselineLeakage.toFixed(0)}% to {mlLeakage.toFixed(0)}%.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-br from-[#38BDF8]/10 to-[#0EA5E9]/5 border-[#38BDF8]/30">
            <CardContent className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <Activity className="w-8 h-8 text-[#38BDF8]" />
                <span className="text-2xl font-bold text-[#38BDF8]">{utilityPreserved.toFixed(0)}%</span>
              </div>
              <h4 className="font-semibold text-[#F8FAFC] mb-2">Utility Preserved</h4>
              <p className="text-sm text-[#94A3B8]">
                Benign task success remains at {utilityPreserved.toFixed(0)}%, showing minimal impact on normal operations.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-br from-[#8B5CF6]/10 to-[#7C3AED]/5 border-[#8B5CF6]/30">
            <CardContent className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <TrendingUp className="w-8 h-8 text-[#8B5CF6]" />
                <span className="text-2xl font-bold text-[#8B5CF6]">{latencyOverhead.toFixed(0)}ms</span>
              </div>
              <h4 className="font-semibold text-[#F8FAFC] mb-2">Latency Overhead</h4>
              <p className="text-sm text-[#94A3B8]">
                ML-assisted protection adds {latencyOverhead.toFixed(0)}ms over no defense, while keeping the recommendation clear:
                {` ${recommendation}`}
              </p>
            </CardContent>
          </Card>
        </div>

        <p className="mt-8 text-center text-sm text-[#64748B]">
          Live values are sourced from <code>/api/metrics</code>.
        </p>
      </div>
    </section>
  );
};

export default MetricsDashboard;
