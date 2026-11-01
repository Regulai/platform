# Dockerfile for regulAI
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For yara-python
    libyara-dev \
    yara \
    # For pytesseract (OCR)
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-spa \
    # For Pillow
    libjpeg-dev \
    zlib1g-dev \
    libpng-dev \
    # For lxml
    libxml2-dev \
    libxslt1-dev \
    # General build tools
    gcc \
    g++ \
    make \
    # For healthcheck
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
COPY regulai/requirements.txt ./regulai_requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt || pip install --no-cache-dir -r regulai_requirements.txt

# Copy project
COPY . .

# Create directories for static files and media
RUN mkdir -p /app/regulai/staticfiles /app/regulai/media

# Set working directory to Django project
WORKDIR /app/regulai

# Copy entrypoint script and fix line endings (Windows compatibility)
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh

# Expose port
EXPOSE 8000

# Run entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]
