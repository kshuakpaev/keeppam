FROM python:3.11-alpine
WORKDIR /app
COPY probe_server.py .
ENV PORT=8100
EXPOSE 8100
CMD ["python3", "-u", "probe_server.py"]
