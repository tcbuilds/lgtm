import shutil
import subprocess

import requests
from flask import request


requests.get(service_url)
subprocess.run(["tool"])
request_data = request.get_json()
cursor.execute(f"SELECT * FROM events WHERE id = {request_data['id']}")

while True:
    process_next_job()

shutil.rmtree(target_directory)
