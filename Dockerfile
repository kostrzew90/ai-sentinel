FROM python:3.12.16-slim
WORKDIR /app
COPY pyproject.toml ./
COPY sentinel ./sentinel
COPY tests ./tests
COPY scenarios ./scenarios
COPY scripts ./scripts
RUN pip install --no-cache-dir ".[dev]"
EXPOSE 8000
CMD ["uvicorn", "sentinel.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
