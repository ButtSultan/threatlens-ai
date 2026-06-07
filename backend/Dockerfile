FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for uploads and reports
RUN mkdir -p /app/uploads /app/reports

# Run database migrations, seed default data, then start server
CMD ["sh", "-c", "alembic upgrade head && python -m app.utils.seed && uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2"]
