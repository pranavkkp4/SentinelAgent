/**
 * SentinelAgent API Service
 *
 * Handles all communication with the FastAPI backend.
 * Configured for both local development and production deployments.
 */

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export type DefenseConfigKey = 'no_defense' | 'prompt_only' | 'rule_based' | 'ml_assisted';

export interface AttackComparisonResult {
  blocked: boolean;
  success: boolean;
  leaked_secrets: number;
  unsafe_tools: number;
  response: string;
}

export interface AttackSimulationResponseData {
  success: boolean;
  result: {
    id?: string;
    attack_type: string;
    payload: string;
    success: boolean;
    defense_triggered: boolean;
    leaked_secrets: string[];
    unsafe_tools_called: string[];
    response: string;
    defense_config: string;
    timestamp?: string;
  };
  comparison?: {
    with_defense?: AttackComparisonResult;
    without_defense?: AttackComparisonResult;
    protection_summary?: {
      attack_blocked: boolean;
      secrets_protected: boolean;
      unsafe_tools_prevented: boolean;
    };
  };
}

export interface MetricsResponseData {
  timestamp: string;
  security_metrics: {
    attack_success_rate: Record<DefenseConfigKey, number>;
    secret_leakage_rate: Record<DefenseConfigKey, number>;
    unsafe_tool_rate: Record<DefenseConfigKey, number>;
  };
  performance_metrics: {
    benign_task_success_rate: Record<DefenseConfigKey, number>;
    latency_ms: Record<DefenseConfigKey, number>;
    throughput_qps: Record<DefenseConfigKey, number>;
  };
  comparison: {
    improvements: {
      ml_assisted: {
        asr_reduction: string;
        leakage_reduction: string;
        utility_preserved: string;
      };
    };
    recommendation: string;
  };
}

class ApiService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = API_BASE;
  }

  private async fetch<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });

      if (!response.ok) {
        const error = await response.text();
        return { success: false, error };
      }

      const data = await response.json();
      return { success: true, data };
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Network error' 
      };
    }
  }

  // Health check
  async healthCheck() {
    return this.fetch<Record<string, unknown>>('/health');
  }

  // Get system stats
  async getStats() {
    return this.fetch<Record<string, unknown>>('/api/stats');
  }

  // Query the agent
  async queryAgent(query: string, enableDefense: boolean = true) {
    return this.fetch<Record<string, unknown>>('/api/query', {
      method: 'POST',
      body: JSON.stringify({ query, enable_defense: enableDefense }),
    });
  }

  // Evaluate attack demo
  async evaluateAttack(attackType: string, payload: string, defenseConfig: string = 'ml-assisted') {
    return this.fetch<AttackSimulationResponseData>('/api/demo/evaluate', {
      method: 'POST',
      body: JSON.stringify({ 
        attack_type: attackType, 
        payload, 
        defense_config: defenseConfig 
      }),
    });
  }

  // Get attack types
  async getAttackTypes() {
    return this.fetch<Record<string, unknown>>('/api/demo/attack-types');
  }

  // Get metrics
  async getMetrics() {
    return this.fetch<MetricsResponseData>('/api/metrics');
  }

  // Screen content
  async screenContent(content: string, contentType: string = 'text') {
    return this.fetch<Record<string, unknown>>('/api/security/screen', {
      method: 'POST',
      body: JSON.stringify({ content, content_type: contentType }),
    });
  }

  // Search documents
  async searchDocuments(query: string, topK: number = 5) {
    return this.fetch<Record<string, unknown>>(`/api/documents/search?query=${encodeURIComponent(query)}&top_k=${topK}`);
  }
}

export const api = new ApiService();
export default api;
