FROM aquasec/trivy:latest AS trivy

FROM python:3.11-slim

# Copy the official Trivy binary into our Python execution environment
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Install Git for repository cloning
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
