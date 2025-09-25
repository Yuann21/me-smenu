# ✅ 1단계: 빌드 단계 (Gradle + JDK 21)
FROM gradle:8.12.1-jdk21 AS builder
WORKDIR /app
COPY . .
RUN gradle clean build -x test

# ✅ 2단계: 실행 단계 (경량화된 OpenJDK 21)
FROM openjdk:21-jdk-slim
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]