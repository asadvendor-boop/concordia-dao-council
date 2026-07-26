"""Run Verity, the Concordia risk and legal agent."""
import asyncio
from agents.verity import main

if __name__ == "__main__":
    asyncio.run(main())
