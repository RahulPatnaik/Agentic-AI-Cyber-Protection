"""
Main entry point for Agentic Threat Modeling System
Run the FastAPI server
"""

from dotenv import load_dotenv
import uvicorn
from src.config import Settings

# Load .env file explicitly
load_dotenv()

if __name__ == "__main__":
    settings = Settings()

    uvicorn.run(
        "src.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
        log_level=settings.log_level.lower()
    )
