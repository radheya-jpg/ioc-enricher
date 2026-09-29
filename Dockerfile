# IOC Enricher — containerized for consistent execution anywhere.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (better layer caching — only reinstalls
# when requirements.txt actually changes, not on every code edit)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Now copy the actual application code
COPY . .

# Cache and logs are written at runtime — keep them out of the image
# itself by pointing at a mounted volume path if the user wants
# persistence across container runs (see README for `docker run -v ...`)
ENV IOC_ENRICHER_LOG_FILE=""

ENTRYPOINT ["python3", "enrich.py"]
CMD ["--help"]
