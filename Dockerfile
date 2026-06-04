FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap dnsutils whois curl wget git unzip \
    gcc g++ make libffi-dev libssl-dev \
    libpango-1.0-0 libpangoft2-1.0-0 \
    libpangocairo-1.0-0 libcairo2 libffi8 \
    shared-mime-info fonts-liberation fonts-dejavu-core \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip \
    && unzip -q nuclei_3.2.4_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm -f nuclei_3.2.4_linux_amd64.zip \
    && nuclei -update-templates -silent || true


RUN pip install --upgrade pip wheel setuptools
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /tmp/uploads /app/scanner_api/scan_results

EXPOSE 8000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
