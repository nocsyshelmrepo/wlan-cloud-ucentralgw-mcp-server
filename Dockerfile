# Use official Python runtime as base image
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser

# Set working directory
WORKDIR /app

# Install only runtime system dependencies (including bash for entrypoint script)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    bash \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/mcpuser/.local

# Copy application code
COPY server.py .
COPY config.yaml .

# Create necessary directories and set permissions
RUN mkdir -p /app/logs /app/config \
    && chown -R mcpuser:mcpuser /app

# Set environment variables
ENV PATH=/home/mcpuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER mcpuser

# Expose port
EXPOSE 5050

CMD ["python", "server.py", "--config", "config.yaml"] 