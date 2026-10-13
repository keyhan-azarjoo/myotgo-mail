FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mailapp ./mailapp

# The app runs as root inside the container only to edit the mail server's account files
# (owned by root) and remove deleted mailboxes; compose drops every other capability and
# makes the filesystem read-only.
EXPOSE 8443
CMD ["python", "-m", "mailapp.main"]
