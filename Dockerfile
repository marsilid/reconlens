FROM python:3.13-slim

RUN useradd --create-home reconlens
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && mkdir -p /app/reports \
    && chown reconlens /app/reports

USER reconlens
ENTRYPOINT ["reconlens"]
CMD ["--help"]
