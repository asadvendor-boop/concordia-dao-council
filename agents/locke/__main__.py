"""Run Locke, the Concordia Casper execution agent."""
import asyncio
from agents.locke import main

if __name__ == "__main__":
    asyncio.run(main())
