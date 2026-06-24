FROM python:3.11-slim

WORKDIR /app

# dependencias del sistema
RUN apt-get update && apt-get install -y gcc

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_ENV=production
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=7700

EXPOSE 7700

CMD ["python", "app.py"]