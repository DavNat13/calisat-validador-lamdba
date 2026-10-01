# --- Etapa de compilacion ---
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app

# Primero solo el POM: mientras el codigo cambie, la capa de dependencias
# descargadas se reutiliza y no se vuelve a resolver todo.
COPY pom.xml .
RUN mvn -B dependency:go-offline

COPY src ./src

# Los tests se ejecutan a proposito. Esta es la unica verificacion de que el
# codigo compila y levanta el contexto con Java 21 real, ya que la maquina que
# lo empaqueta puede tener otro JDK instalado.
RUN mvn -B clean package

# --- Etapa final: solo el JAR ---
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# maven-shade-plugin escribe el artefacto sombreado en target/function.jar (nombre
# fijo, configurado con outputFile en el pom). El layout plano (clases en la raiz,
# sin BOOT-INF/lib) es el que entiende el runtime java21 gestionado de Lambda; el
# repackage de spring-boot-maven-plugin generaria un JAR que ese runtime no lee.
COPY --from=build /app/target/function.jar /app/function.jar

# La imagen solo sirve para inspeccionar/probar el artefacto y para extraerlo con
# "docker cp" (ver build.sh). Lo que se despliega en Lambda es el JAR
# /app/function.jar con Runtime: java21 y Handler:
# com.lambda.validador.AuthorizerHandler::handleRequest
CMD ["sh", "-c", "ls -la /app/function.jar && java -version"]
