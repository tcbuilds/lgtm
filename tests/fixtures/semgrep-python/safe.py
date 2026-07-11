import shutil
import subprocess

import requests
from flask import request


requests.get(service_url, timeout=10)
subprocess.run(["tool"], timeout=10)
request_data = request.get_json()
validated_data = request_schema.load(request_data)
cursor.execute("SELECT * FROM events WHERE id = %s", (validated_data["id"],))

for _ in range(max_attempts):
    process_next_job()

if confirmed:
    shutil.rmtree(target_directory)
