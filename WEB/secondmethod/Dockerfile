FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

WORKDIR /app

# copy your code into container
COPY snapworker.py /app/

# install playwright python bindings
RUN pip install --no-cache-dir playwright

# (optional) install browsers inside image, but base image usually includes them
RUN playwright install --with-deps chromium

CMD ["python", "snapworker.py"]
