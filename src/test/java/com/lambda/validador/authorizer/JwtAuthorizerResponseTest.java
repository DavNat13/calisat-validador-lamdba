package com.lambda.validador.authorizer;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import com.lambda.validador.security.JwtValidationService;
import com.lambda.validador.security.MultiIssuerJwtDecoder;
import com.lambda.validador.support.TestTokens;

/**
 * Contrato de SALIDA del authorizer: exactamente {"isAuthorized": true|false} y
 * nada mas, que es lo que un authorizer de HTTP API con
 * "EnableSimpleResponses: true" y payload 2.0 exige leer.
 *
 * <p>Ni "context" ni ningun claim: el backend vuelve a validar el token, y copiar
 * aqui la identidad solo la escribiria en los access logs de API Gateway.</p>
 */
class JwtAuthorizerResponseTest {

    private static final String ISSUER = "https://login.example.com/tenant/v2.0";
    private static final TestTokens TOKENS = TestTokens.generar();

    /** Decoder que siempre valida: aqui lo que se prueba es la respuesta. */
    private JwtAuthorizerFunction authorizerQueAcepta() {
        return authorizer(valor -> jwtValido());
    }

    private JwtAuthorizerFunction authorizer(JwtDecoder decoder) {
        return new JwtAuthorizerFunction(new JwtValidationService(new MultiIssuerJwtDecoder(Map.of(ISSUER, decoder))));
    }

    /** Token firmado cuyo unico proposito es llegar al enrutador. */
    private String token() {
        return TOKENS.firmar(ISSUER, null, Map.of(), Instant.now().plusSeconds(3600));
    }

    private Jwt jwtValido() {
        return Jwt.withTokenValue(token())
                .header("alg", "RS256")
                .issuedAt(Instant.now().minusSeconds(60))
                .expiresAt(Instant.now().plusSeconds(3600))
                .claim("iss", ISSUER)
                .claim("sub", "usuario-1")
                .build();
    }

    private APIGatewayV2CustomAuthorizerEvent evento(String authorization) {
        APIGatewayV2CustomAuthorizerEvent event = new APIGatewayV2CustomAuthorizerEvent();
        event.setVersion("2.0");
        event.setType("REQUEST");
        event.setRouteArn("arn:aws:execute-api:us-east-1:123456789012:abcdef/test/GET/pedidos");
        event.setRawPath("/pedidos");
        if (authorization != null) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("authorization", authorization);
            event.setHeaders(headers);
        }
        return event;
    }

    @Test
    void autorizaCuandoElTokenEsValido() {
        assertThat(authorizerQueAcepta().authorize(evento("Bearer " + token())).isAuthorized()).isTrue();
    }

    @Test
    void laRespuestaAutorizadaEsSoloElBooleano() {
        String json = serializa(authorizerQueAcepta().authorize(evento("Bearer " + token())));

        assertThat(json).isEqualTo("{\"isAuthorized\":true}");
    }

    @Test
    void laRespuestaDenegadaEsSoloElBooleano() {
        String json = serializa(authorizerQueAcepta().authorize(evento(null)));

        assertThat(json).isEqualTo("{\"isAuthorized\":false}");
    }

    @Test
    void noSeEscapaNingunClaimDelTokenEnLaRespuesta() {
        Jwt conDatos = Jwt.withTokenValue(token())
                .header("alg", "RS256")
                .issuedAt(Instant.now().minusSeconds(60))
                .expiresAt(Instant.now().plusSeconds(3600))
                .claim("iss", ISSUER)
                .claim("sub", "usuario-1")
                .claim("preferred_username", "alguien@ejemplo.cl")
                .claim("roles", List.of("Administrador"))
                .claim("scp", "write-read")
                .build();

        String json = serializa(authorizer(valor -> conDatos).authorize(evento("Bearer " + token())));

        assertThat(json).isEqualTo("{\"isAuthorized\":true}");
    }

    private String serializa(AuthorizerResult result) {
        return tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(result);
    }
}
