"""Compatibility entrypoint for ``python -m agents.safety_reviewer``."""

import asyncio

from agents.verity import main

if __name__ == "__main__":
    asyncio.run(main())
