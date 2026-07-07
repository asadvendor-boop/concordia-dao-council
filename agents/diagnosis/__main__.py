"""Compatibility entrypoint for ``python -m agents.diagnosis``."""

import asyncio

from agents.mercer import main

if __name__ == "__main__":
    asyncio.run(main())
