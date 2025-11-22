import logging

# Global logging config
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

from cve_notifier.main import main

if __name__ == "__main__":
    main()
