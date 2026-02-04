import asyncio

from obj.DDosDetector import Config
from obj.DDosDetector import DDosDetector
from obj.Logger import logger

async def main():
    config = Config()
    
    async with DDosDetector(config) as detector:
        try:
            await detector.run()
        except KeyboardInterrupt:
            logger.info("Shutting down gracefully...")

if __name__ == '__main__':
    asyncio.run(main())