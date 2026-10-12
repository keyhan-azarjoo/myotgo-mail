FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

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
