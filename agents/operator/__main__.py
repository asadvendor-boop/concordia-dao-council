"""Compatibility entrypoint for ``python -m agents.operator``."""

import asyncio

from agents.locke import main

if __name__ == "__main__":
    asyncio.run(main())
