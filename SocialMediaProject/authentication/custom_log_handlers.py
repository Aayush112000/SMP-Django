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
import schedule
from threading import Timer

class CustomTimedRotatingFileHandler(TimedRotatingFileHandler):
    def __init__(self, filename, when='M', interval=1, backupCount=0, encoding=None, delay=False, utc=False, atTime=None):
        super().__init__(filename, when, interval, backupCount, encoding, delay, utc, atTime)
    
        self.old_files = []
    
    def doRollover(self):
        """
        Override the original method to customize the log file naming convention.
        """
        now = datetime.now()
        now = now
        current_time_format = datetime.now().strftime('%Y%m%d%H%M%S')
        current_time_format = current_time_format

        if self.stream:
            self.stream.close()
            self.stream = None

        # Get the current log file name
        current_log_file = self.baseFilename
  
        # Generate the new log file name with project name and timestamp
        new_log_file = f"SMP_{current_time_format}.txt"
        new_log_path = os.path.join(settings.LOGGING_DIR, new_log_file)

        # Copy the content of the old log file to the new log file
        with open(current_log_file, 'r') as old_file, open(new_log_path, 'w') as new_file:
            shutil.copyfileobj(old_file, new_file)
        
        # Change the baseFilename to the new log file path
        self.baseFilename = new_log_path
        
        if not self.delay:
            self.stream = self._open()

        next_rollover_time = datetime.now() + timedelta(minutes=self.interval)
        self.rolloverAt = next_rollover_time.timestamp()

        Timer(60, self.doRollover).start()

        # Store references to the last three log files
        self.old_files.append(current_log_file)
        if len(self.old_files) > 3:
            # Delete the oldest log file
            file_to_delete = self.old_files.pop(0)
            os.remove(file_to_delete)