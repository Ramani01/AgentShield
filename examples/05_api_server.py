"""
Example 05: FastAPI Server Initialization and Health Check.
"""

from agentshield.api import create_app

def main():
    print("=== AgentShield REST API Server Example ===")
    app = create_app()
    print("FastAPI application instance successfully created!")
    print("To start the server, run: uvicorn examples.05_api_server:app --reload")
    return app

app = create_app()

if __name__ == "__main__":
    main()
