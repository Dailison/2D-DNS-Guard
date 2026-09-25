FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER 65534
EXPOSE 8080
CMD ["gunicorn", "-w", "2", "--threads", "8", "-b", "0.0.0.0:8080", "--timeout", "90", "wsgi:app"]
