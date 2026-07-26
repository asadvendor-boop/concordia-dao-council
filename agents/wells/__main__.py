"""Run Wells, the Governance Archivist."""
import asyncio
from agents.wells import main

if __name__ == "__main__":
    asyncio.run(main())
