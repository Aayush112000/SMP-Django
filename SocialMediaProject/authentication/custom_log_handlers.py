import logging
import os
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime,timedelta
from django.conf import settings

import os
import time
from logging.handlers import TimedRotatingFileHandler
import shutil
import fileinput

class CustomTimedRotatingFileHandler(TimedRotatingFileHandler):
    def __init__(self, filename, when='M', interval=30, backupCount=0, encoding=None, delay=False, utc=False, atTime=None):
        super().__init__(filename, when, interval, backupCount, encoding, delay, utc, atTime)

    def doRollover(self):
        """
        Override the original method to customize the log file naming convention.
        """
        now = datetime.now() 
        current_time_format = datetime.now().strftime('%Y%m%d%H%M%S')

        if self.stream:
            self.stream.close()
            self.stream = None

        # Get the current log file name
        current_log_file = self.baseFilename
  
        # Generate the new log file name with project name and timestamp
        new_log_file = f"SMP_{current_time_format}.txt"
        new_log_path = os.path.join(settings.LOGGING_DIR, new_log_file)

        os.rename(current_log_file, new_log_path)
        
        # Change the baseFilename to the new log file path
        self.baseFilename = new_log_path

        if not self.delay:
            self.stream = self._open()

        next_rollover_time = now + timedelta(minutes=self.interval)
        self.rolloverAt = self.computeRollover(next_rollover_time.timestamp())