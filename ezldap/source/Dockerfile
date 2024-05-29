FROM eclipse-temurin:17.0.11_9-jdk-alpine

COPY app /app
COPY start.sh /start.sh

EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/start.sh"]
