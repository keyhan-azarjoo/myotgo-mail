FROM python:3.13-slim

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
