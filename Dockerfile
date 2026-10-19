FROM python:3.11-slim

# Install system dependencies (ping ICMP, openssh-client, tzdata)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    openssh-client \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Set default timezone ke Asia/Jakarta
ENV TZ=Asia/Jakarta
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# Copy dependencies & install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY app ./app

# Directory untuk data SQLite permanen
RUN mkdir -p /app/data
ENV DATA_DIR=/app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
