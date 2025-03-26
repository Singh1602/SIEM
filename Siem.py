# Lightweight SIEM System
# Requirements: elasticsearch, logstash, kibana, python-elasticsearch, python-logstash

import os
import json
import logging
from datetime import datetime
from elasticsearch import Elasticsearch
from logstash import LogstashHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogCollector(FileSystemEventHandler):
    def __init__(self, es_client, logstash_handler):
        self.es = es_client
        self.logstash = logstash_handler
        self.logger = logging.getLogger('siem_logger')
        self.logger.addHandler(self.logstash)
        self.logger.setLevel(logging.INFO)

    def on_modified(self, event):
        if event.is_directory:
            return
        self.process_log_file(event.src_path)

    def process_log_file(self, filepath):
        try:
            with open(filepath, 'r') as f:
                log_data = f.read()
                normalized_data = self.normalize_log_data(log_data)
                self.store_in_elasticsearch(normalized_data)
                self.check_alerts(normalized_data)
        except Exception as e:
            print(f"Error processing log file: {e}")

    def normalize_log_data(self, log_data):
        # Add custom normalization logic based on log format
        return {
            'timestamp': datetime.now().isoformat(),
            'source': 'system_logs',
            'data': log_data,
            'normalized': True
        }

    def store_in_elasticsearch(self, data):
        try:
            self.es.index(index='siem_logs', body=data)
        except Exception as e:
            print(f"Error storing in Elasticsearch: {e}")

    def check_alerts(self, data):
        # Add custom alert rules here
        alert_rules = [
            {'pattern': 'failed login', 'severity': 'high'},
            {'pattern': 'unauthorized access', 'severity': 'critical'},
        ]

        for rule in alert_rules:
            if rule['pattern'] in str(data).lower():
                self.trigger_alert(rule, data)

    def trigger_alert(self, rule, data):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': rule['severity'],
            'message': f"Alert: {rule['pattern']} detected",
            'data': data
        }
        self.logger.warning(f"Security Alert: {json.dumps(alert)}")

def setup_siem():
    # Initialize Elasticsearch client
    es = Elasticsearch(['localhost:9200'])

    # Initialize Logstash handler
    logstash = LogstashHandler('localhost', 5000, version=1)

    # Initialize log collector
    collector = LogCollector(es, logstash)

    # Set up file system observer
    observer = Observer()
    observer.schedule(collector, path='/var/log', recursive=False)
    observer.start()

    return observer, collector

def main():
    print("Starting Lightweight SIEM System...")
    observer, collector = setup_siem()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
        observer.join()

if __name__ == "__main__":
    main()

"""
Setup Instructions:

1. Install required components:
   - Elasticsearch: https://www.elastic.co/downloads/elasticsearch
   - Logstash: https://www.elastic.co/downloads/logstash
   - Kibana: https://www.elastic.co/downloads/kibana

2. Install Python dependencies:
   pip install elasticsearch python-logstash watchdog

3. Configure Elasticsearch:
   - Start Elasticsearch service
   - Verify it's running at localhost:9200

4. Configure Logstash:
   - Create a logstash.conf file with input/output settings
   - Start Logstash with the configuration

5. Configure Kibana:
   - Start Kibana service
   - Access dashboard at localhost:5601
   - Create visualizations for log data

6. Run the SIEM system:
   python siem_system.py

Note: Adjust paths and configurations according to your environment.
"""
