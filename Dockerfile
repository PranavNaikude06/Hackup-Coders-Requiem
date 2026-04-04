FROM python:3.11-slim

# Install system packages required for some python native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the requirements first to cache the pip install layer
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir torch==2.4.0 --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy the rest of the backend source code
COPY backend/ ./backend/

# Set working directory to backend so `app.main:app` can be resolved
WORKDIR /app/backend

# Make sure we don't buffer Python output so logs appear instantly
ENV PYTHONUNBUFFERED=1

# Run the app. Railway provides the $PORT environment variable dynamically.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
