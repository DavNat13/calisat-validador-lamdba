package com.lambda.validador.authorizer;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import com.lambda.validador.security.JwtValidationService;

/**
 * Filtro de entrada de AWS API Gateway HTTP API.
 *
 * <p>Su unica funcion es decidir si la peticion sigue hacia la integracion: si el
 * JWT es valido, deja pasar; si no, la bloquea. No extrae claims ni arma contexto
 * porque el backend vuelve a validar el token y se encarga de eso.</p>
 *
 * <p>Cualquier fallo deniega: una excepcion inesperada nunca debe dejar pasar una
 * peticion sin validar. Se registra en CloudWatch para poder distinguir "token
 * invalido" de "error de configuracion".</p>
 */
public class JwtAuthorizerFunction {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthorizerFunction.class);

    private static final String BEARER_PREFIX = "bearer ";

    private final JwtValidationService validator;

    /**
     * Esta clase no se registra como bean de Spring: la resuelve Spring Cloud
     * Function a traves del bean Function registrado en AuthorizerConfiguration.
     *
     * <p>No lleva constructor sin argumentos a proposito. El runtime de Lambda
     * solo instancia por reflexion las clases que el Handler declara, y el
     * Handler de esta funcion es el FunctionInvoker de Spring Cloud Function,
     * no esta. Anadirlo crearia una instancia sin validar configuracion, con el
     * decoder a null: cada peticion acabaria en isAuthorized false por un
     * NullPointerException tragado, es decir, un 403 para todo el mundo sin que
     * nada en los logs lo delatara.</p>
     */
    public JwtAuthorizerFunction(JwtValidationService validator) {
        this.validator = validator;
    }

    public AuthorizerResult authorize(APIGatewayV2CustomAuthorizerEvent event) {
        String token = extraerToken(event);

        if (token == null) {
            log.warn("Peticion rechazada: no llega cabecera Authorization");
            return AuthorizerResult.denied();
        }

        try {
            validator.validate(token);
            return AuthorizerResult.allowed();
        } catch (Exception e) {
            log.error("Peticion rechazada: el token no supero la validacion", e);
            return AuthorizerResult.denied();
        }
    }

    /**
     * API Gateway entrega las cabeceras en minusculas, pero se busca sin
     * distinguir mayusculas para no depender de ese detalle. El prefijo "Bearer "
     * llega intacto: el authorizer REQUEST no lo quita por nosotros.
     */
    private String extraerToken(APIGatewayV2CustomAuthorizerEvent event) {
        Map<String, String> headers = event.getHeaders();
        if (headers == null) {
            return null;
        }

        String authorization = headers.entrySet().stream()
                .filter(header -> "authorization".equalsIgnoreCase(header.getKey()))
                .map(Map.Entry::getValue)
                .filter(valor -> valor != null && !valor.isBlank())
                .findFirst()
                .orElse(null);

        if (authorization == null) {
            return null;
        }

        String token = authorization.trim();
        if (token.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            token = token.substring(BEARER_PREFIX.length()).trim();
        }

        return token.isEmpty() ? null : token;
    }
}
