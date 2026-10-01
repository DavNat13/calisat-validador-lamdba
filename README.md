# calisat-validador-lambda

## 1. Descripción

Lambda Authorizer en **Java 21** para **Amazon API Gateway (HTTP API)** con autenticación **dual**:
**Microsoft Entra ID** (Azure) + **AWS Cognito**. Responde siempre la respuesta simple
`{"isAuthorized": true}` o `{"isAuthorized": false}` (sin `policyDocument`, `statusCode` ni
`context`), con **payload 2.0** y *Simple responses* habilitadas.

## 2. Arquitectura / cómo valida

1. API Gateway invoca la función con el evento **REQUEST** y le entrega la cabecera `Authorization`
   como *identity source* (`$request.header.Authorization`).
2. `AuthorizerHandler` (implementa `RequestStreamHandler`) arranca Spring **una sola vez** (frío)
   y delega en la función `jwtAuthorizer`.
3. Se extrae el token `Bearer <jwt>` y se lee **solo el claim `iss`, sin verificar la firma**, para
   elegir el proveedor: `login.microsoftonline.com/<tenant>/v2.0` → Entra ID;
   `cognito-idp.<region>.amazonaws.com/<pool>` → Cognito.
4. El proveedor aporta su **JWKS** (`jwk-set-uri`) y con él se validan **firma, `aud`, `iss` y
   fechas (`exp`/`nbf`/`iat`)**. El JWKS se descarga de internet (la Lambda no usa VPC).
5. Válido → `{"isAuthorized": true}`; ausente/mal formado/caducado → `false` → API Gateway **401**.
6. API Gateway cachea la decisión el *TTL* del autorizador (por defecto 300 s).

## 3. Construcción del artefacto

Se compila **en contenedor** (Java 21 real, sin depender del JDK local; los tests corren a propósito):

```bash
./build.sh
```

Equivalente manual (extrae el JAR con un contenedor temporal):

```bash
docker build -t lambda-builder .
docker create --name temp-container lambda-builder
docker cp temp-container:/app/function.jar ./function.jar
docker rm temp-container
```

Resultado: `./function.jar` (maven-shade, clases en la raíz; en la imagen queda `/app/function.jar`,
producido desde `target/function.jar`).

## 4. Despliegue en AWS (consola)

### a) Crear la función
1. **Lambda → Crear función → Autorizar desde cero**.
2. Nombre: `validador-authorizer` · Runtime: **Java 21** · Arquitectura: **x86_64** o **arm64**
   (el JAR es Java puro: corre igual en ambas; `template.yaml` usa `arm64`).
3. Rol: **Configuración avanzada → Rol de ejecución personalizado → seleccionar `labRole`**
   (si no aparece, crearlo en IAM con `AWSLambdaBasicExecutionRole` y recargar).
4. **Crear función**.

### b) Código de la función
1. **Código de la función → Subir desde → .zip o archivo .jar → Upload**.
2. Selecciona `function.jar` (raíz del proyecto, generado por `build.sh`).
3. Pulsa **Deploy** (arriba a la derecha) y espera el aviso de despliegue correcto.

### c) Configuración → Handler
1. **Configuración → Editar → Configuración de la versión ejecutable**.
2. Controlador (Handler): `com.lambda.validador.AuthorizerHandler::handleRequest`.
3. **Guardar** → aviso *"esta acción sobrescribirá el código desplegado"* → aceptar → **Deploy**
   de nuevo para que el cambio surta efecto.

### d) Autorizador en API Gateway (HTTP API)
1. **API Gateway → tu HTTP API → Autorización → Crear autorizador**.
2. Tipo: **Lambda** → selecciona la función creada → **Crear autorizador**.
3. **Formato de versión de carga útil (Payload format version): 2.0**.
4. **Habilitar respuestas simples (Enable simple responses): Simple**.
5. **Origen de identidad (Identity source): `$request.header.Authorization`**.
6. **TTL de caché**: 300 s (opcional; `0` valida la firma en cada petición).

### e) Adjuntar el autorizador a las rutas `/api/v1/...`
1. En **Rutas**, seleccionar cada ruta existente → **Acciones → Adjuntar autorizador** →
   el autorizador recién creado. Para cubrir toda la API de una vez, fijarlo como
   **autorizador por defecto ($default)**.
2. Si alguna ruta debe quedar pública, seleccionarla → **Acciones → Quitar autorizador**.

### f) Prueba
```bash
API=https://ho5p58iyu7.execute-api.us-east-1.amazonaws.com
curl -i -H "Authorization: Bearer $TOKEN_VALIDO"  $API/api/v1/usuarios/perfil   # pasa (llega al backend)
curl -i -H "Authorization: Bearer $TOKEN_INVALIDO" $API/api/v1/usuarios/perfil  # 401 (isAuthorized false)
curl -i $API/api/v1/usuarios/perfil                                              # 400 (falta cabecera)
```

## 5. Variables de entorno / proveedores

Viven en `src/main/resources/application.yaml` y se sobrescriben con *relaxed binding*
(`APP_SECURITY_JWT_PROVIDERS_<indice>_<PROPIEDAD>`) en **Lambda → Configuración → Variables de
entorno → Editar**. Valores de nuestra arquitectura:

| # | Proveedor | Valor |
|---|-----------|-------|
| 0 | Entra ID: tenant | `e5372bf0-c5e3-4286-887c-79069f209c1f` |
| 0 | Entra ID: audience | `d221f0d2-1a7c-4872-ad6c-367a1f0717ec` |
| 1 | Cognito: user pool | `us-east-1_UK0Q6EmAQ` |
| 1 | Cognito: client id | `79rbb9f5e2l5nmak9d17ueb2se` |

```bash
APP_SECURITY_JWT_PROVIDERS_0_JWKSETURI=https://login.microsoftonline.com/e5372bf0-c5e3-4286-887c-79069f209c1f/discovery/v2.0/keys
APP_SECURITY_JWT_PROVIDERS_0_ISSUERS_0=https://login.microsoftonline.com/e5372bf0-c5e3-4286-887c-79069f209c1f/v2.0
APP_SECURITY_JWT_PROVIDERS_0_AUDIENCES_0=d221f0d2-1a7c-4872-ad6c-367a1f0717ec
APP_SECURITY_JWT_PROVIDERS_1_JWKSETURI=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_UK0Q6EmAQ/.well-known/jwks.json
APP_SECURITY_JWT_PROVIDERS_1_ISSUERS_0=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_UK0Q6EmAQ
APP_SECURITY_JWT_PROVIDERS_1_AUDIENCES_0=79rbb9f5e2l5nmak9d17ueb2se
```

Notas: `JWKSETURI` equivale a `jwk-set-uri`; en Cognito el app client figura como `aud` en el ID
token y como `client_id` en el access token (el authorizer acepta ambos).

## 6. Estructura del proyecto

```
calisat-validador-lambda/
├── pom.xml  mvnw  mvnw.cmd  .mvn/wrapper/maven-wrapper.properties
├── Dockerfile  build.sh  template.yaml  .gitignore  .gitattributes  README.md
└── src/
    ├── main/
    │   ├── java/com/lambda/validador/
    │   │   ├── AuthorizerHandler.java          # handler + respuesta simple
    │   │   ├── ValidadorApplication.java
    │   │   ├── authorizer/  (AuthorizerConfiguration, AuthorizerResult,
    │   │   │                 JwtAuthorizerFunction)
    │   │   └── security/    (JwtProviderProperties, JwtValidationService,
    │   │                     MultiIssuerJwtDecoder, SecurityConfiguration)
    │   └── resources/application.yaml          # proveedores JWT
    └── test/java/com/lambda/validador/
        ├── AuthorizerHandlerTest.java  ValidadorApplicationTests.java
        ├── authorizer/  (JwtAuthorizerFunctionTest, JwtAuthorizerResponseTest)
        ├── security/    (JwtValidationServiceTest, MultiIssuerJwtDecoderTest)
        └── support/     (JwksServer, TestTokens)
```

## 7. Versionamiento con git

```bash
git status
git add .            # o sólo los archivos que quieras versionar
git commit -m "feat: lambda authorizer dual Entra ID + Cognito (Java 21)"
git log --oneline -10
git push origin main
```
