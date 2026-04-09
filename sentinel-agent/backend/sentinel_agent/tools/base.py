"""Base tool interface for SentinelAgent."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ToolResult:
    """Result from tool execution."""
    success: bool
    data: Any
    error: str = ""
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data if isinstance(self.data, (str, int, float, bool, list, dict, type(None))) else str(self.data),
            "error": self.error,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ToolSchema:
    """Schema defining a tool's interface."""
    name: str
    description: str
    parameters: Dict[str, Any]
    required: list = field(default_factory=list)
    returns: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "required": self.required,
            "returns": self.returns
        }


class BaseTool(ABC):
    """Base class for all tools."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.schema = self._define_schema()
        self.execution_count = 0
        self.total_execution_time_ms = 0.0
    
    @abstractmethod
    def _define_schema(self) -> ToolSchema:
        """Define the tool's schema."""
        pass
    
    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        """Execute the tool."""
        pass
    
    def get_schema(self) -> Dict[str, Any]:
        """Get tool schema as dict."""
        return self.schema.to_dict()
    
    def validate_args(self, args: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validate tool arguments against schema.
        
        Returns:
            Tuple of (valid, error_message)
        """
        # Check required parameters
        for param in self.schema.required:
            if param not in args:
                return False, f"Missing required parameter: {param}"
        
        # Check parameter types
        for param, value in args.items():
            if param in self.schema.parameters:
                expected_type = self.schema.parameters[param].get("type")
                if expected_type and not self._check_type(value, expected_type):
                    return False, f"Parameter '{param}' has wrong type, expected {expected_type}"
        
        return True, ""
    
    def _check_type(self, value: Any, expected_type: str) -> bool:
        """Check if value matches expected type."""
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict
        }
        
        expected = type_map.get(expected_type)
        if expected:
            return isinstance(value, expected)
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get tool execution statistics."""
        avg_time = (self.total_execution_time_ms / max(self.execution_count, 1))
        return {
            "name": self.name,
            "execution_count": self.execution_count,
            "total_execution_time_ms": round(self.total_execution_time_ms, 2),
            "avg_execution_time_ms": round(avg_time, 2)
        }


class ToolRegistry:
    """Registry for managing available tools."""
    
    def __init__(self):
        self.tools: Dict[str, BaseTool] = {}
    
    def register(self, tool: BaseTool):
        """Register a tool."""
        self.tools[tool.name] = tool
    
    def unregister(self, name: str):
        """Unregister a tool."""
        if name in self.tools:
            del self.tools[name]
    
    def get(self, name: str) -> Optional[BaseTool]:
        """Get a tool by name."""
        return self.tools.get(name)
    
    def list_tools(self) -> list:
        """List all registered tools."""
        return [tool.get_schema() for tool in self.tools.values()]
    
    def get_all_schemas(self) -> Dict[str, Dict[str, Any]]:
        """Get schemas for all tools."""
        return {name: tool.get_schema() for name, tool in self.tools.items()}
