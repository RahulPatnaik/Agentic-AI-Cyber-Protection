"""
Main entry point for Improved Agentic Threat Modeling System
Run the FastAPI server with tree-sitter chunking and improved components
"""

from dotenv import load_dotenv
import uvicorn
from src.config import Settings

# Load .env file explicitly
load_dotenv()

if __name__ == "__main__":
    settings = Settings()

    uvicorn.run(
        "src.api.app_improved:app",  # Use the improved app
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
        log_level=settings.log_level.lower()
    )