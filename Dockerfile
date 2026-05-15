FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install httpx fastmcp pydantic

# Copy the server script
COPY strety_mcp.py .

# Default command — runs the MCP server
CMD ["python", "strety_mcp.py"]