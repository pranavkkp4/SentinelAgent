"""Agent Orchestrator for SentinelAgent.

Implements the Plan-Act-Observe loop for task execution.
"""

import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..models import TaskResult, TaskStatus, ToolCall, Document, SecurityCheck
from ..security import SecurityMiddleware
from ..security.defense_profiles import get_defense_profile
from ..retrieval import RetrievalSubsystem
from ..tools import ToolRegistry, create_default_tools
from ..config import config


class AgentStep(Enum):
    """Agent execution steps."""
    PLAN = "plan"
    RETRIEVE = "retrieve"
    THINK = "think"
    ACT = "act"
    OBSERVE = "observe"
    RESPOND = "respond"


@dataclass
class ExecutionContext:
    """Context for task execution."""
    query: str
    step_count: int = 0
    max_steps: int = 20
    retrieved_documents: List[Document] = field(default_factory=list)
    tool_calls: List[ToolCall] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    security_checks: List[SecurityCheck] = field(default_factory=list)
    memory: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "step_count": self.step_count,
            "max_steps": self.max_steps,
            "retrieved_documents": len(self.retrieved_documents),
            "tool_calls": len(self.tool_calls),
            "tool_calls_in_session": len(self.tool_calls),
            "recent_tool_calls": [
                {"tool_name": call.tool_name, "risk_score": call.risk_score}
                for call in self.tool_calls[-5:]
            ],
            "observations": self.observations,
            "memory": self.memory,
            "task_type": self.memory.get("task_type", ""),
            "defense_config": self.memory.get("defense_config", ""),
        }


class AgentOrchestrator:
    """
    Agent orchestrator implementing Plan-Act-Observe loop.
    
    Features:
    - Step-limited execution
    - Security middleware integration
    - Tool use with risk assessment
    - Document retrieval with filtering
    - Comprehensive logging
    """
    
    def __init__(self, 
                 security_middleware: Optional[SecurityMiddleware] = None,
                 retrieval_subsystem: Optional[RetrievalSubsystem] = None,
                 tool_registry: Optional[ToolRegistry] = None):
        
        self.security = security_middleware or SecurityMiddleware()
        self.retrieval = retrieval_subsystem or RetrievalSubsystem()
        self.tools = tool_registry or ToolRegistry()
        
        # Register default tools
        default_tools = create_default_tools(self.retrieval)
        for tool in default_tools.values():
            self.tools.register(tool)
        
        self.execution_history: List[TaskResult] = []
        self.canary_tokens = config.security.canary_tokens
    
    async def execute(
        self,
        query: str,
        enable_defense: bool = True,
        defense_config: str = "ml-assisted",
    ) -> TaskResult:
        """
        Execute a user query through the agent.
        
        Args:
            query: User query
            enable_defense: Whether to enable security middleware
            defense_config: Named defense profile for evaluation/demo metadata
            
        Returns:
            TaskResult with execution results
        """
        start_time = time.time()
        profile = get_defense_profile(defense_config, enable_defense=enable_defense)
        effective_detection = enable_defense and profile.enable_detection
        
        # Initialize execution context
        context = ExecutionContext(
            query=query,
            max_steps=config.agent.max_steps,
            memory={
                "canary_tokens": self.canary_tokens,
                "task_type": self._infer_task_type(query),
                "defense_config": profile.name,
                "defense_profile": profile.label,
            }
        )
        
        result = TaskResult(
            query=query,
            status=TaskStatus.RUNNING
        )

        if effective_detection:
            input_check = self.security.injection_detector.detect(
                query,
                context=profile.to_detection_context(source="user_query"),
            )
            result.security_checks.append(input_check)
            context.security_checks.append(input_check)

            if profile.enforce_input and input_check.details.get("security_level") == "malicious":
                result.blocked = True
                result.block_reason = "Malicious query detected before execution"
                result.status = TaskStatus.BLOCKED
                result.response = "[Query blocked due to malicious input]"
                result.steps_taken = context.step_count
                result.execution_time_ms = (time.time() - start_time) * 1000
                result.metrics = self._compute_metrics(context)
                self.execution_history.append(result)
                return result
        
        try:
            # Main execution loop
            while context.step_count < context.max_steps:
                context.step_count += 1
                
                # Step 1: Plan - determine next action
                action = await self._plan(context)
                
                if action["type"] == "respond":
                    # Generate final response
                    response = await self._generate_response(context)
                    
                    # Screen response if defense enabled
                    if effective_detection and profile.use_exfiltration_detector:
                        screened_response, check = self.security.screen_response(
                            response,
                            context.tool_calls,
                            enforce=profile.enforce_response,
                            profile=profile,
                        )
                        context.security_checks.append(check)
                        result.security_checks.append(check)

                        if profile.enforce_response:
                            response = screened_response
                            release_decision = self.security.make_release_decision(
                                response,
                                check,
                                enforce=profile.enforce_response,
                                profile=profile,
                            )

                            if not release_decision.allow:
                                result.blocked = True
                                result.block_reason = release_decision.reason
                                result.status = TaskStatus.BLOCKED
                                response = "[Response blocked due to security concerns]"
                    
                    result.response = response
                    if result.status != TaskStatus.BLOCKED:
                        result.status = TaskStatus.COMPLETED
                    break
                    
                elif action["type"] == "retrieve":
                    # Retrieve documents
                    docs, checks = await self._retrieve_documents(
                        action.get("query", query),
                        effective_detection,
                        profile,
                    )
                    context.retrieved_documents.extend(docs)
                    context.security_checks.extend(checks)
                    result.security_checks.extend(checks)
                    result.documents_retrieved.extend(docs)
                    
                elif action["type"] == "tool_call":
                    # Execute tool with security checks
                    tool_result = await self._execute_tool(
                        action.get("tool_name"),
                        action.get("arguments", {}),
                        context,
                        profile
                    )
                    
                    if tool_result:
                        context.tool_calls.append(tool_result)
                        result.tools_used.append(tool_result)
                        context.observations.append(
                            f"Tool {tool_result.tool_name}: {tool_result.reason}"
                        )
                        
                        # Check if blocked
                        if not tool_result.allowed:
                            result.blocked = True
                            result.block_reason = f"Tool call blocked: {tool_result.reason}"
                            result.status = TaskStatus.BLOCKED
                            break
                
                # Check for termination conditions
                if context.step_count >= context.max_steps:
                    result.response = "Task exceeded maximum step limit."
                    result.status = TaskStatus.FAILED
                    break
            
        except Exception as e:
            result.status = TaskStatus.FAILED
            result.response = f"Execution error: {str(e)}"
        
        # Finalize result
        result.steps_taken = context.step_count
        result.execution_time_ms = (time.time() - start_time) * 1000
        result.metrics = self._compute_metrics(context)
        
        self.execution_history.append(result)
        
        return result
    
    async def _plan(self, context: ExecutionContext) -> Dict[str, Any]:
        """
        Plan next action based on context.
        
        This is a simplified planning logic. In production, this would
        use an LLM to decide the next action.
        """
        query = context.query.lower()
        
        # Simple rule-based planning
        if context.step_count == 1:
            # First step: retrieve relevant documents
            if any(kw in query for kw in ["search", "find", "look up", "document", "information about", "summarize this document"]):
                return {"type": "retrieve", "query": query}
            
            # Check if we need calculation
            if self._has_keyword(query, ["calculate", "compute", "sum", "total", "math"]):
                return {
                    "type": "tool_call",
                    "tool_name": "calculator",
                    "arguments": {"expression": self._extract_expression(query)}
                }

            if self._has_keyword(query, ["analyze", "analysis", "statistics", "average", "mean"]):
                return {
                    "type": "tool_call",
                    "tool_name": "analyze_data",
                    "arguments": {
                        "data": self._extract_data_payload(context.query),
                        "analysis_type": "statistics" if any(
                            keyword in query for keyword in ["statistics", "average", "mean"]
                        ) else "summary",
                    }
                }
            
            # Check if we need web fetch
            if self._has_keyword(query, ["web", "website", "url", "page", "fetch"]):
                return {
                    "type": "tool_call",
                    "tool_name": "web_fetch",
                    "arguments": {"url": self._extract_url(query)}
                }
            
            # Check if we need to send message
            if self._has_keyword(query, ["send", "email", "message", "notify"]):
                return {
                    "type": "tool_call",
                    "tool_name": "send_message",
                    "arguments": {
                        "recipient": self._extract_recipient(query),
                        "content": self._extract_message_content(query)
                    }
                }
        
        # Default: respond
        return {"type": "respond"}
    
    async def _retrieve_documents(
        self,
        query: str,
        enable_defense: bool,
        profile,
    ) -> tuple[List[Document], List[SecurityCheck]]:
        """Retrieve and screen documents."""
        # Retrieve documents
        result = self.retrieval.retrieve(query)
        
        if not enable_defense:
            return result.documents, []
        
        # Screen with security middleware
        filtered_docs, checks = self.security.screen_retrieved_content(
            result.documents,
            detector_mode=profile.detector_mode,
            enforce=profile.enforce_retrieval,
            profile=profile,
        )
        
        return filtered_docs, checks
    
    async def _execute_tool(self, tool_name: str, arguments: Dict,
                           context: ExecutionContext, profile) -> Optional[ToolCall]:
        """Execute a tool with security checks."""
        # Get tool
        tool = self.tools.get(tool_name)
        if not tool:
            return ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                allowed=False,
                reason=f"Tool '{tool_name}' not found",
                risk_score=1.0
            )
        
        # Validate arguments
        valid, error = tool.validate_args(arguments)
        if not valid:
            return ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                allowed=False,
                reason=f"Invalid arguments: {error}",
                risk_score=0.8
            )
        
        # Security evaluation
        if profile.enable_detection and (
            profile.use_tool_risk_classifier or profile.use_exfiltration_detector
        ):
            tool_call = self.security.evaluate_tool_call(
                tool_name,
                arguments,
                context.to_dict(),
                use_exfiltration_detector=profile.use_exfiltration_detector,
                enforce=profile.enforce_tools,
                use_tool_risk_classifier=profile.use_tool_risk_classifier,
                profile=profile,
            )
            
            if not tool_call.allowed and profile.enforce_tools:
                return tool_call
        else:
            tool_call = ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                allowed=True,
                reason=(
                    "Defense disabled"
                    if not profile.enable_detection
                    else "Tool-risk classifier disabled by defense profile"
                ),
                risk_score=0.0
            )
        
        # Execute tool
        try:
            tool_result = await tool.execute(**arguments)
            tool_call.metadata["result"] = tool_result.to_dict()
        except Exception as e:
            tool_call.metadata["error"] = str(e)
        
        return tool_call
    
    async def _generate_response(self, context: ExecutionContext) -> str:
        """Generate response based on context."""
        # Simplified response generation
        # In production, this would use an LLM
        
        parts = []
        
        # Add context from retrieved documents
        if context.retrieved_documents:
            parts.append("Based on the retrieved information:")
            for doc in context.retrieved_documents[:2]:
                parts.append(f"- From {doc.source}: {doc.content[:200]}...")
        
        # Add observations from tool calls
        if context.tool_calls:
            parts.append("\nTool execution results:")
            for tc in context.tool_calls:
                result = tc.metadata.get("result", {}).get("data")
                details = result if result not in (None, "") else tc.reason
                parts.append(f"- {tc.tool_name}: {details}")

        if not parts:
            parts.append("No tool or retrieval actions were required.")

        parts.append("\nTask completed successfully.")
        
        return "\n".join(parts)
    
    def _compute_metrics(self, context: ExecutionContext) -> Dict[str, Any]:
        """Compute execution metrics."""
        return {
            "documents_retrieved": len(context.retrieved_documents),
            "tool_calls": len(context.tool_calls),
            "security_checks": len(context.security_checks),
            "steps": context.step_count
        }
    
    # Helper methods for extracting information from queries
    def _extract_expression(self, query: str) -> str:
        """Extract mathematical expression from query."""
        import re
        candidates = [
            candidate.strip()
            for candidate in re.findall(r'[\d\.\s\+\-\*\/\^\(\)]+', query)
            if re.search(r'\d', candidate) and any(op in candidate for op in "+-*/^")
        ]
        if candidates:
            return max(candidates, key=len)

        numbers = re.findall(r'\d+(?:\.\d+)?', query)
        if len(numbers) >= 2:
            if "sum" in query or "add" in query or "plus" in query:
                return f"{numbers[0]} + {numbers[1]}"
            if "subtract" in query or "minus" in query:
                return f"{numbers[0]} - {numbers[1]}"
            if "multiply" in query or "times" in query:
                return f"{numbers[0]} * {numbers[1]}"
            if "divide" in query or "over" in query:
                return f"{numbers[0]} / {numbers[1]}"

        return "1 + 1"
    
    def _extract_url(self, query: str) -> str:
        """Extract URL from query."""
        import re
        url_pattern = r'https?://[^\s]+'
        match = re.search(url_pattern, query)
        if match:
            return match.group(0)
        # Return a default allowed domain
        return "https://example.com"
    
    def _extract_recipient(self, query: str) -> str:
        """Extract recipient from query."""
        import re
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        match = re.search(email_pattern, query)
        return match.group(0) if match else "user@example.com"
    
    def _extract_message_content(self, query: str) -> str:
        """Extract message content from query."""
        # Simple extraction
        return "Message from SentinelAgent"

    def _extract_data_payload(self, query: str) -> str:
        """Extract the data segment for the analysis tool."""
        import re

        structured = re.search(r"(\[[^\]]+\]|\{[^\}]+\})", query)
        if structured:
            return structured.group(1)
        if ":" in query:
            return query.split(":", 1)[1].strip()
        return query

    def _has_keyword(self, query: str, keywords: List[str]) -> bool:
        """Match keywords conservatively to avoid substring collisions."""
        import re

        for keyword in keywords:
            if " " in keyword:
                if keyword in query:
                    return True
            elif re.search(rf"\b{re.escape(keyword)}\b", query):
                return True
        return False

    def _infer_task_type(self, query: str) -> str:
        """Infer a coarse task type for policy checks."""
        query_lower = query.lower()
        if self._has_keyword(query_lower, ["calculate", "compute", "sum", "total", "math"]):
            return "calculation"
        if self._has_keyword(query_lower, ["send", "email", "message", "notify"]):
            return "communication"
        if self._has_keyword(query_lower, ["analyze", "analysis", "statistics"]):
            return "analysis"
        if self._has_keyword(query_lower, ["search", "find", "look up", "fetch", "document"]):
            return "search"
        return "general"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "total_executions": len(self.execution_history),
            "successful": sum(1 for r in self.execution_history if r.status == TaskStatus.COMPLETED),
            "failed": sum(1 for r in self.execution_history if r.status == TaskStatus.FAILED),
            "blocked": sum(1 for r in self.execution_history if r.status == TaskStatus.BLOCKED),
            "avg_execution_time_ms": sum(r.execution_time_ms for r in self.execution_history) / max(len(self.execution_history), 1)
        }
