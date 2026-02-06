import asyncio

from ddos_killer.DDosDetector import Config
from ddos_killer.DDosDetector import DDosDetector
from ddos_killer.Logger import logger

async def main():
    config = Config()
    
    async with DDosDetector(config) as detector:
        try:
            await detector.run()
        except KeyboardInterrupt:
            logger.info("Shutting down gracefully...")

if __name__ == '__main__':
    asyncio.run(main())