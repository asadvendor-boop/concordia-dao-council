"""Run the presentation-only Wells roster heartbeat."""
import asyncio
from agents.wells import main

if __name__ == "__main__":
    asyncio.run(main())
