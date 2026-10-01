#!/usr/bin/env bash
#
# Construye el JAR de la Lambda dentro de un contenedor (Java 21 real, sin
# depender del JDK de la maquina local) y lo extrae a ./function.jar.
#
# Uso:
#   ./build.sh
#
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Construyendo la imagen (ejecuta mvn -B clean package con los tests)"
docker build -t lambda-builder .

echo "==> Creando un contenedor temporal a partir de la imagen"
docker create --name temp-container lambda-builder

echo "==> Extrayendo /app/function.jar a ./function.jar"
docker cp temp-container:/app/function.jar ./function.jar

echo "==> Eliminando el contenedor temporal"
docker rm temp-container

echo "==> listo: $(pwd)/function.jar"
ls -la ./function.jar
