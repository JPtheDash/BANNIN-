# Deliberately misconfigured Dockerfile so Trivy's misconfig scanner has
# something to flag (:latest tag, root user, no HEALTHCHECK).
FROM python:latest
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
