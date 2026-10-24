FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
ENV PORT=8000 DB_PATH=/srv/data/brandsentry.db
EXPOSE 8000
CMD ["python", "-m", "app.server"]
