FROM amazoncorretto:21-alpine-jdk

COPY target/EncrypterMylo-1.0.0-STABLE.jar /api-v1.jar

ENTRYPOINT ["java", "-jar", "/api-v1.jar"]