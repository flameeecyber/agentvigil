FROM python:3.12-slim
WORKDIR /app
COPY vigil ./vigil
COPY examples ./examples
COPY pyproject.toml README.md LICENSE ./
RUN pip install --no-cache-dir . && vigil --help
ENTRYPOINT ["vigil"]
EXPOSE 8000
CMD ["serve", "examples/evil-repo", "--host", "0.0.0.0", "--port", "8000"]
