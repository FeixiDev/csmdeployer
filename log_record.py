#! /usr/bin/env python3
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import datetime

# 获取当前脚本所在的目录
current_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
log_directory = os.path.join(current_directory, "logs")  # 日志文件夹路径

if not os.path.exists(log_directory):
    os.makedirs(log_directory)  # 如果文件夹不存在，创建它


class Logger:
    def __init__(self, task_name, debug_enabled=False):
        self.logger = logging.getLogger(f"Debug_{task_name}")
        self.logger.setLevel(logging.DEBUG)
        self.name = f"log-{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
        self.debug_log_file = os.path.join(log_directory, self.name)
        self.debug_enabled = debug_enabled  # Set initial debug state

        file_handler = RotatingFileHandler(
            self.debug_log_file, maxBytes=1000 * 1024 * 1024, backupCount=5)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def log(self, message):
        self.logger.debug(message)

