"""Tool implementations for SentinelAgent."""

import time
import json
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from .base import BaseTool, ToolSchema, ToolResult
from ..config import config


class CalculatorTool(BaseTool):
    """Simple calculator tool for mathematical expressions."""
    
    def __init__(self):
        super().__init__(
            name="calculator",
            description="Evaluate mathematical expressions safely"
        )
    
    def _define_schema(self) -> ToolSchema:
        return ToolSchema(
            name="calculator",
            description="Evaluate mathematical expressions safely",
            parameters={
                "expression": {
                    "type": "string",
                    "description": "Mathematical expression to evaluate"
                }
            },
            required=["expression"],
            returns={
                "type": "number",
                "description": "Result of the calculation"
            }
        )
    
    async def execute(self, expression: str) -> ToolResult:
        """Execute calculation."""
        start_time = time.time()
        
        try:
            # Sanitize expression
            sanitized = self._sanitize_expression(expression)
            
            # Safe evaluation
            result = self._safe_eval(sanitized)
            
            execution_time = (time.time() - start_time) * 1000
            self.execution_count += 1
            self.total_execution_time_ms += execution_time
            
            return ToolResult(
                success=True,
                data=result,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return ToolResult(
                success=False,
                data=None,
                error=str(e),
                execution_time_ms=execution_time
            )
    
    def _sanitize_expression(self, expression: str) -> str:
        """Sanitize mathematical expression."""
        # Remove any non-math characters
        allowed = set('0123456789+-*/.()^ sqrtpowlogsin costan ')
        sanitized = ''.join(c for c in expression if c in allowed)
        return sanitized
    
    def _safe_eval(self, expression: str) -> float:
        """Safely evaluate mathematical expression."""
        # Replace common functions
        expr = expression.replace('^', '**')
        
        # Only allow basic operations
        allowed_names = {
            "sqrt": lambda x: x ** 0.5,
            "pow": pow,
            "abs": abs,
            "max": max,
            "min": min
        }
        
        # Compile and evaluate
        code = compile(expr, "<string>", "eval")
        
        # Check for disallowed names
        for name in code.co_names:
            if name not in allowed_names and name not in ('True', 'False', 'None'):
                raise ValueError(f"Disallowed name in expression: {name}")
        
        return eval(code, {"__builtins__": {}}, allowed_names)


class WebFetchTool(BaseTool):
    """Web fetching tool with domain restrictions."""
    
    def __init__(self, allowed_domains: Optional[list] = None):
        super().__init__(
            name="web_fetch",
            description="Fetch content from web pages (restricted to allowed domains)"
        )
        self.allowed_domains = set(allowed_domains or config.security.allowed_domains)

    def _is_allowed_domain(self, domain: str) -> bool:
        normalized = domain.lower().split(":")[0]
        return any(
            normalized == allowed.lower() or normalized.endswith(f".{allowed.lower()}")
            for allowed in self.allowed_domains
        )
    
    def _define_schema(self) -> ToolSchema:
        return ToolSchema(
            name="web_fetch",
            description="Fetch content from web pages (restricted to allowed domains)",
            parameters={
                "url": {
                    "type": "string",
                    "description": "URL to fetch"
                },
                "max_length": {
                    "type": "integer",
                    "description": "Maximum content length to return",
                    "default": 5000
                }
            },
            required=["url"],
            returns={
                "type": "string",
                "description": "Fetched content"
            }
        )
    
    async def execute(self, url: str, max_length: int = 5000) -> ToolResult:
        """Execute web fetch."""
        import asyncio
        start_time = time.time()
        
        try:
            # Validate URL
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check domain allowlist
            allowed = self._is_allowed_domain(domain)
            
            if not allowed:
                return ToolResult(
                    success=False,
                    data=None,
                    error=f"Domain '{domain}' not in allowlist",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Simulate web fetch (in production, use httpx/aiohttp)
            # For demo, return simulated content
            await asyncio.sleep(0.1)  # Simulate network delay
            
            content = self._simulate_fetch(url, max_length)
            
            execution_time = (time.time() - start_time) * 1000
            self.execution_count += 1
            self.total_execution_time_ms += execution_time
            
            return ToolResult(
                success=True,
                data=content,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return ToolResult(
                success=False,
                data=None,
                error=str(e),
                execution_time_ms=execution_time
            )
    
    def _simulate_fetch(self, url: str, max_length: int) -> str:
        """Simulate fetching content from URL."""
        return f"""Content from {url}:
This is simulated web content for demonstration purposes.
In a production environment, this would contain actual fetched content.
URL: {url}
Fetched at: {time.strftime('%Y-%m-%d %H:%M:%S')}
Content length limited to: {max_length} characters
"""


class DocumentSearchTool(BaseTool):
    """Tool for searching indexed documents."""
    
    def __init__(self, retrieval_subsystem=None):
        super().__init__(
            name="document_search",
            description="Search for documents in the knowledge base"
        )
        self.retrieval = retrieval_subsystem
    
    def _define_schema(self) -> ToolSchema:
        return ToolSchema(
            name="document_search",
            description="Search for documents in the knowledge base",
            parameters={
                "query": {
                    "type": "string",
                    "description": "Search query"
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of results to return",
                    "default": 5
                }
            },
            required=["query"],
            returns={
                "type": "array",
                "description": "List of matching documents"
            }
        )
    
    async def execute(self, query: str, top_k: int = 5) -> ToolResult:
        """Execute document search."""
        import asyncio
        start_time = time.time()
        
        try:
            if self.retrieval is None:
                return ToolResult(
                    success=False,
                    data=None,
                    error="Retrieval subsystem not available",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Perform search
            result = self.retrieval.retrieve(query, top_k=top_k)
            
            # Format results
            documents = [
                {
                    "id": doc.id,
                    "content": doc.content[:500] + "..." if len(doc.content) > 500 else doc.content,
                    "source": doc.source,
                    "metadata": doc.metadata
                }
                for doc in result.documents
            ]
            
            execution_time = (time.time() - start_time) * 1000
            self.execution_count += 1
            self.total_execution_time_ms += execution_time
            
            return ToolResult(
                success=True,
                data={
                    "documents": documents,
                    "total_found": result.total_found,
                    "search_time_ms": round(result.search_time_ms, 2)
                },
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return ToolResult(
                success=False,
                data=None,
                error=str(e),
                execution_time_ms=execution_time
            )


class SendMessageTool(BaseTool):
    """Simulated message sending tool (logs only, no actual sending)."""
    
    def __init__(self):
        super().__init__(
            name="send_message",
            description="Send a message (simulated - logs only)"
        )
        self.message_log = []
    
    def _define_schema(self) -> ToolSchema:
        return ToolSchema(
            name="send_message",
            description="Send a message (simulated - logs only)",
            parameters={
                "recipient": {
                    "type": "string",
                    "description": "Message recipient"
                },
                "content": {
                    "type": "string",
                    "description": "Message content"
                },
                "subject": {
                    "type": "string",
                    "description": "Message subject",
                    "default": ""
                }
            },
            required=["recipient", "content"],
            returns={
                "type": "object",
                "description": "Message send confirmation"
            }
        )
    
    async def execute(self, recipient: str, content: str, subject: str = "") -> ToolResult:
        """Execute message send (simulated)."""
        start_time = time.time()
        
        try:
            # Validate recipient
            if not self._validate_recipient(recipient):
                return ToolResult(
                    success=False,
                    data=None,
                    error=f"Invalid recipient format: {recipient}",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Log message (don't actually send)
            message = {
                "recipient": recipient,
                "subject": subject,
                "content": content[:100] + "..." if len(content) > 100 else content,
                "timestamp": time.time()
            }
            self.message_log.append(message)
            
            execution_time = (time.time() - start_time) * 1000
            self.execution_count += 1
            self.total_execution_time_ms += execution_time
            
            return ToolResult(
                success=True,
                data={
                    "status": "logged",
                    "recipient": recipient,
                    "message_id": f"msg_{len(self.message_log)}",
                    "note": "Message was logged but not actually sent (sandbox mode)"
                },
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return ToolResult(
                success=False,
                data=None,
                error=str(e),
                execution_time_ms=execution_time
            )
    
    def _validate_recipient(self, recipient: str) -> bool:
        """Validate recipient format."""
        # Allow email or simple identifiers
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, recipient)) or len(recipient) > 2


class DataAnalysisTool(BaseTool):
    """Tool for analyzing data."""
    
    def __init__(self):
        super().__init__(
            name="analyze_data",
            description="Analyze data and extract insights"
        )
    
    def _define_schema(self) -> ToolSchema:
        return ToolSchema(
            name="analyze_data",
            description="Analyze data and extract insights",
            parameters={
                "data": {
                    "type": "string",
                    "description": "Data to analyze (JSON or text)"
                },
                "analysis_type": {
                    "type": "string",
                    "description": "Type of analysis",
                    "enum": ["summary", "statistics", "extract", "count"]
                }
            },
            required=["data", "analysis_type"],
            returns={
                "type": "object",
                "description": "Analysis results"
            }
        )
    
    async def execute(self, data: str, analysis_type: str) -> ToolResult:
        """Execute data analysis."""
        start_time = time.time()
        
        try:
            # Try to parse as JSON
            try:
                parsed_data = json.loads(data)
            except json.JSONDecodeError:
                parsed_data = data
            
            # Perform analysis
            if analysis_type == "summary":
                result = self._summarize(parsed_data)
            elif analysis_type == "statistics":
                result = self._statistics(parsed_data)
            elif analysis_type == "extract":
                result = self._extract(parsed_data)
            elif analysis_type == "count":
                result = self._count(parsed_data)
            else:
                result = {"error": f"Unknown analysis type: {analysis_type}"}
            
            execution_time = (time.time() - start_time) * 1000
            self.execution_count += 1
            self.total_execution_time_ms += execution_time
            
            return ToolResult(
                success=True,
                data=result,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return ToolResult(
                success=False,
                data=None,
                error=str(e),
                execution_time_ms=execution_time
            )
    
    def _summarize(self, data: Any) -> Dict:
        """Generate summary of data."""
        if isinstance(data, list):
            return {
                "type": "list",
                "length": len(data),
                "sample": data[:3] if data else []
            }
        elif isinstance(data, dict):
            return {
                "type": "object",
                "keys": list(data.keys()),
                "key_count": len(data)
            }
        else:
            text = str(data)
            return {
                "type": "text",
                "length": len(text),
                "word_count": len(text.split()),
                "preview": text[:200]
            }
    
    def _statistics(self, data: Any) -> Dict:
        """Calculate statistics."""
        if isinstance(data, list) and all(isinstance(x, (int, float)) for x in data):
            return {
                "count": len(data),
                "sum": sum(data),
                "mean": sum(data) / len(data) if data else 0,
                "min": min(data) if data else None,
                "max": max(data) if data else None
            }
        return {"error": "Statistics require numeric list"}
    
    def _extract(self, data: Any) -> Dict:
        """Extract structured information."""
        return {
            "extracted": str(data)[:500],
            "type": type(data).__name__
        }
    
    def _count(self, data: Any) -> Dict:
        """Count elements."""
        if isinstance(data, list):
            return {"count": len(data)}
        elif isinstance(data, dict):
            return {"key_count": len(data)}
        elif isinstance(data, str):
            return {"char_count": len(data), "word_count": len(data.split())}
        return {"count": 1}


def create_default_tools(retrieval_subsystem=None) -> Dict[str, BaseTool]:
    """Create default set of tools."""
    tools = {
        "calculator": CalculatorTool(),
        "web_fetch": WebFetchTool(),
        "document_search": DocumentSearchTool(retrieval_subsystem),
        "send_message": SendMessageTool(),
        "analyze_data": DataAnalysisTool()
    }
    return tools
