"""Compatibility entrypoint for ``python -m agents.triage``."""

import asyncio

from agents.rowan import main

if __name__ == "__main__":
    asyncio.run(main())
