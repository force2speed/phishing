# Dockerfile
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

# copy requirements (minimal)
COPY <<EOF requirements.txt
playwright
EOF

RUN pip install -r requirements.txt && playwright install --with-deps chromium

# small worker script
COPY snapworker.py /app/snapworker.py

ENTRYPOINT ["python3", "/app/snapworker.py"]
