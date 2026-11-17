FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
