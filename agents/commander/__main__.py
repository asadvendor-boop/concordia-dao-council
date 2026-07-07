"""Compatibility entrypoint for ``python -m agents.commander``."""

import asyncio

from agents.alden import main

if __name__ == "__main__":
    asyncio.run(main())
