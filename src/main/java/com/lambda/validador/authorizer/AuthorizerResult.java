package com.lambda.validador.authorizer;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Respuesta de un Lambda authorizer de HTTP API con
 * "EnableSimpleResponses: true" y "AuthorizerPayloadFormatVersion: 2.0".
 *
 * <p>API Gateway no espera un statusCode ni un policyDocument: interpreta el
 * cuerpo y solo mira "isAuthorized".</p>
 *
 * <p>No se devuelve "context" a proposito. Este authorizer actua como filtro de
 * entrada: el backend vuelve a validar el token y extrae los claims, de modo que
 * copiar aqui la identidad no aportaria nada y ademas escribiria esos datos en
 * los access logs de API Gateway.</p>
 *
 * <p>El nombre de la propiedad debe ser exactamente "isAuthorized" en minuscula
 * inicial: un "Context" en mayuscula se ignora en silencio.</p>
 */
public record AuthorizerResult(@JsonProperty("isAuthorized") boolean isAuthorized) {

    public static AuthorizerResult allowed() {
        return new AuthorizerResult(true);
    }

    public static AuthorizerResult denied() {
        return new AuthorizerResult(false);
    }
}
