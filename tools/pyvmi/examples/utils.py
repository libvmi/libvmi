import logging
from contextlib import contextmanager


def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)


@contextmanager
def pause(vmi):
    vmi.pause_vm()
    try:
        yield
    finally:
        vmi.resume_vm()
