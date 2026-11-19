FROM python:3.15-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy application code
COPY services/ /app/services/

# Create non-root user
RUN useradd -m -u 1000 tenet && chown -R tenet:tenet /app
USER tenet

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "services.ingest.app:app", "--host", "0.0.0.0", "--port", "8000"]
