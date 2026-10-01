package com.lambda.validador.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import com.lambda.validador.support.JwksServer;
import com.lambda.validador.support.TestTokens;

/**
 * Validacion de extremo a extremo contra un JWK Set real publicado en localhost:
 * firma, emisor, audiencia y caducidad se comprueban de verdad, no simuladas.
 */
class JwtValidationServiceTest {

    private static final TestTokens TOKENS = TestTokens.generar();
    private static JwksServer jwks;

    /** Un solo decoder por proveedor, montado sobre el JWKS local de pruebas. */
    private static JwtValidationService servicio(String... audiences) {
        JwtProviderProperties.Provider provider = new JwtProviderProperties.Provider();
        provider.setName("pruebas");
        provider.setJwkSetUri(jwks.url());
        provider.setIssuers(List.of(TestTokens.ISSUER));
        provider.setAudiences(List.of(audiences));

        JwtProviderProperties properties = new JwtProviderProperties();
        properties.setProviders(List.of(provider));
        return new JwtValidationService(JwtValidationService.construirDecoder(properties));
    }

    @BeforeAll
    static void publicarJwks() {
        jwks = TestTokens.publicarJwks(TOKENS.jwks());
    }

    @AfterAll
    static void apagarJwks() {
        jwks.close();
    }

    @Test
    void aceptaUnTokenValido() {
        Jwt jwt = servicio(TestTokens.AUDIENCE).validate(
                TOKENS.firmar(TestTokens.claims("sub", "usuario-1", "scope", "lectura")));

        assertThat(jwt.getSubject()).isEqualTo("usuario-1");
        assertThat(jwt.getIssuer().toString()).isEqualTo(TestTokens.ISSUER);
    }

    @Test
    void rechazaUnTokenCaducado() {
        assertThatThrownBy(() -> servicio(TestTokens.AUDIENCE)
                .validate(TOKENS.firmarExpirado(Map.of())))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void rechazaUnTokenEmitidoParaOtraApi() {
        assertThatThrownBy(() -> servicio(TestTokens.AUDIENCE)
                .validate(TOKENS.firmar(TestTokens.ISSUER, TestTokens.OTRO_AUDIENCE, Map.of(), Instant.now().plusSeconds(3600))))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("no fue emitido para este backend");
    }

    @Test
    void aceptaLaAudienciaEnElClaimClientIdDeCognito() {
        String token = TOKENS.firmar(
                TestTokens.ISSUER,
                null,
                TestTokens.claims("client_id", TestTokens.AUDIENCE),
                Instant.now().plusSeconds(3600));

        Jwt jwt = servicio(TestTokens.AUDIENCE).validate(token);

        assertThat(jwt.getClaimAsString("client_id")).isEqualTo(TestTokens.AUDIENCE);
    }

    @Test
    void rechazaUnTokenFirmadoPorUnaLlaveAjena() {
        TestTokens ajenos = TestTokens.generar();
        String token = ajenos.firmar(TestTokens.claims("scope", "lectura"));

        assertThatThrownBy(() -> servicio(TestTokens.AUDIENCE).validate(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void rechazaUnTokenDeUnEmisorNoRegistrado() {
        assertThatThrownBy(() -> servicio(TestTokens.AUDIENCE).validate(
                TOKENS.firmar("https://atacante.example.com", TestTokens.AUDIENCE, Map.of(), Instant.now().plusSeconds(3600))))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("no fue emitido por un proveedor registrado");
    }

    @Test
    void aceptaCualquieraDeLosVariosEmisoresDeUnProveedor() {
        String segundo = "https://login.otro-tenant.example.com/v2.0";
        JwtProviderProperties.Provider provider = new JwtProviderProperties.Provider();
        provider.setName("pruebas");
        provider.setJwkSetUri(jwks.url());
        provider.setIssuers(List.of(TestTokens.ISSUER, segundo));
        provider.setAudiences(List.of(TestTokens.AUDIENCE));

        JwtProviderProperties properties = new JwtProviderProperties();
        properties.setProviders(List.of(provider));
        JwtValidationService servicio = new JwtValidationService(JwtValidationService.construirDecoder(properties));

        Jwt jwt = servicio.validate(TOKENS.firmar(
                segundo, TestTokens.AUDIENCE, Map.of(), Instant.now().plusSeconds(3600)));

        assertThat(jwt.getIssuer().toString()).isEqualTo(segundo);
    }

    @Test
    void noValidaAudienciaSiElProveedorNoDeclaraNinguna() {
        Jwt jwt = servicio().validate(
                TOKENS.firmar(TestTokens.ISSUER, TestTokens.OTRO_AUDIENCE, Map.of(), Instant.now().plusSeconds(3600)));

        assertThat(jwt).isNotNull();
    }

    @Test
    void validaUnTokenQueTraeClaimsQueElAuthorizerNoMira() {
        Jwt jwt = servicio(TestTokens.AUDIENCE).validate(TOKENS.firmar(TestTokens.claims(
                "sub", "usuario-1",
                "roles", List.of("Admin", "Reportes"),
                "cognito:groups", List.of("Admin"),
                "preferred_username", "alguien@ejemplo.cl")));

        // El backend vuelve a validar el token y extrae estos claims. Aqui solo
        // importa que el token sea valido, y lo es: los claims viajan intactos
        // aunque este authorizer no los mire.
        assertThat(jwt.getSubject()).isEqualTo("usuario-1");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("Admin", "Reportes");
        assertThat(jwt.getClaimAsString("preferred_username")).isEqualTo("alguien@ejemplo.cl");
    }
}
