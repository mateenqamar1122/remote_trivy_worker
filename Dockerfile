FROM aquasec/trivy:latest AS trivy

FROM python:3.11-slim

# Copy the official Trivy binary into our Python execution environment
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Install Git and Curl for repository cloning and OpenGrep installation
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

# Install OpenGrep
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# Clone OpenGrep rules
RUN git clone https://github.com/opengrep/opengrep-rules /opt/opengrep-rules || echo "Rules clone failed, proceeding anyway"

# Add the OpenGrep binary location to the system PATH
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
