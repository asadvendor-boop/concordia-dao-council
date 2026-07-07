"""Run Mercer, the Concordia treasury intelligence agent."""
import asyncio
from agents.mercer import main

if __name__ == "__main__":
    asyncio.run(main())
