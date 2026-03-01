FROM python:3.11-alpine

# Set secure and non-interactive environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app

WORKDIR $APP_HOME

COPY requirements.txt .

# Install dependencies (install build-base temporarily in case cffi needs it)
RUN apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

# Create an unprivileged user and group to run the app (reduce attack surface)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Copy application files
COPY main.py .

EXPOSE 8000

# Start server using uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
