import asyncio
import sys

from .collector import main

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
