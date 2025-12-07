FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
	curl \
	whois \
	openssl \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shodan-dork.py .

CMD ["python", "-u", "shodan-dork.py"]
