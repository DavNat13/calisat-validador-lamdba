package com.lambda.validador.authorizer;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import com.lambda.validador.security.JwtValidationService;
import com.lambda.validador.security.MultiIssuerJwtDecoder;
import com.lambda.validador.support.TestTokens;

/**
 * Contrato de ENTRADA del authorizer: donde busca el token, como interpreta la
 * cabecera Authorization y que hace cuando la validacion falla. La validacion
 * criptografica real se prueba en JwtValidationServiceTest y la forma exacta de
 * la respuesta, en JwtAuthorizerResponseTest.
 *
 * <p>Los tokens se firman de verdad porque el enrutador multi-emisor lee el claim
 * "iss" del token antes de delegar: un texto arbitrario se rechazaria antes de
 * llegar al decoder.</p>
 */
class JwtAuthorizerFunctionTest {

    private static final String ISSUER = "https://login.example.com/tenant/v2.0";
    private static final TestTokens TOKENS = TestTokens.generar();

    private JwtAuthorizerFunction authorizer(JwtDecoder decoder) {
        return new JwtAuthorizerFunction(new JwtValidationService(new MultiIssuerJwtDecoder(Map.of(ISSUER, decoder))));
    }

    /** Decoder que siempre valida: aqui lo que se prueba es la cabecera, no el token. */
    private JwtAuthorizerFunction authorizerQueAcepta() {
        return authorizer(valor -> jwtValido());
    }

    /** Comprueba que el validador recibe el token exacto que se esperaba. */
    private void assertTokenRecibido(String cabecera, String esperado) {
        AtomicReference<String> recibido = new AtomicReference<>();
        JwtAuthorizerFunction authorizer = authorizer(valor -> {
            recibido.set(valor);
            return jwtValido();
        });

        assertThat(authorizer.authorize(evento(cabecera)).isAuthorized()).isTrue();
        assertThat(recibido.get()).isEqualTo(esperado);
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
    void aceptaLaCabeceraEnCualquierCombinacionDeMayusculas() {
        APIGatewayV2CustomAuthorizerEvent event = new APIGatewayV2CustomAuthorizerEvent();
        event.setHeaders(Map.of("Authorization", "Bearer " + token()));

        assertThat(authorizerQueAcepta().authorize(event).isAuthorized()).isTrue();
    }

    @Test
    void quitaElPrefijoBearer() {
        String esperado = token();
        assertTokenRecibido("Bearer " + esperado, esperado);
    }

    @Test
    void aceptaElPrefijoBearerEnMinusculas() {
        String esperado = token();
        assertTokenRecibido("bearer " + esperado, esperado);
    }

    @Test
    void aceptaElTokenSinPrefijo() {
        String esperado = token();
        assertTokenRecibido(esperado, esperado);
    }

    @Test
    void rechazaSiNoLlegaLaCabeceraAuthorization() {
        assertThat(authorizerQueAcepta().authorize(evento(null)).isAuthorized()).isFalse();
    }

    @Test
    void rechazaCabecerasQueNoDejanUnToken() {
        assertThat(authorizerQueAcepta().authorize(evento("   ")).isAuthorized()).isFalse();
        assertThat(authorizerQueAcepta().authorize(evento("Bearer ")).isAuthorized()).isFalse();
        assertThat(authorizerQueAcepta().authorize(evento("bearer")).isAuthorized()).isFalse();
    }

    @Test
    void rechazaCuandoElTokenNoSuperaLaValidacion() {
        JwtDecoder decoder = valor -> {
            throw new JwtException("token invalido");
        };

        assertThat(authorizer(decoder).authorize(evento("Bearer " + token())).isAuthorized()).isFalse();
    }

    @Test
    void rechazaAnteUnErrorInesperadoEnVezDeDejarPasar() {
        JwtDecoder decoder = valor -> {
            throw new IllegalStateException("el JWK Set no responde");
        };

        assertThat(authorizer(decoder).authorize(evento("Bearer " + token())).isAuthorized()).isFalse();
    }

    @Test
    void rechazaUnTokenQueNoEsUnJwt() {
        assertThat(authorizerQueAcepta().authorize(evento("Bearer no-es-un-jwt")).isAuthorized()).isFalse();
    }
}
