import logging
import logging.handlers
import os


def setup_logger():
    logger = logging.getLogger("utbox")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            os.environ["SPLUNK_HOME"] + "/var/log/splunk/utbox.log",
            maxBytes=25000000,
            backupCount=3,
        )
        file_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
    except KeyError:
        logger.error(
            "SPLUNK_HOME environment variable not set. Continuing with only console output."
        )

    return logger
