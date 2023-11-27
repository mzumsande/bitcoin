#!/usr/bin/env python3

import threading
import logging

log = logging.getLogger("TestFramework.threading")

class LogLock(object):
    def __init__(self, name):
        self.name = str(name)
        self.lock = threading.Lock()

    def acquire(self, blocking=True):
        current_thread = threading.current_thread()
        thread_name = current_thread.name
        log.debug("{0:x} Trying to acquire {1} lock, thread {2}".format(
            id(self), self.name, thread_name))
        ret = self.lock.acquire(blocking)
        if ret == True:
            log.debug("{0:x} Acquired {1} lock thread {2}".format(
                id(self), self.name, thread_name))
        else:
            log.debug("{0:x} Non-blocking aquire of {1} lock failed thread {2}".format(
                id(self), self.name, thread_name))
        return ret

    def release(self):
        current_thread = threading.current_thread()
        thread_name = current_thread.name
        log.debug("{0:x} Releasing {1} lock thread {2}".format(id(self), self.name, thread_name))
        self.lock.release()

    def __enter__(self):
        self.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False    # Do not swallow exceptions
