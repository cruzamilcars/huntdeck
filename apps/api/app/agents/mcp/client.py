from typing import Protocol

from app.domain.ioc.types import ParsedIoc
from app.schemas.investigation import McpObservation


class McpClient(Protocol):
    name: str

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        """Query an MCP server adapter and return one normalized observation."""
