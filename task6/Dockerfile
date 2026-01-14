FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for subprocess commands
RUN apt-get update && apt-get install -y procps

# Install Python dependencies
RUN pip install --no-cache-dir mmpy_bot loguru python-dotenv

# Copy all bot files
COPY . .

# Make bot.py executable
RUN chmod +x bot.py

CMD ["python", "bot.py", "-v"]