package com.lambda.validador.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import com.lambda.validador.support.TestTokens;

/**
 * Comprueba el enrutado por "iss" antes de validar la firma: un token de un
 * proveedor no registrado debe rechazarse aunque su firma sea correcta.
 */
class MultiIssuerJwtDecoderTest {

    private static final String ISSUER_A = "https://azure.example.com/tenant/v2.0";
    private static final String ISSUER_B = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST";

    private final TestTokens tokens = TestTokens.generar();

    /** Decoder que falla diciendo a quien llego, para poder observar el enrutado. */
    private JwtDecoder stub(String emisor) {
        return token -> {
            throw new JwtException("llego a " + emisor);
        };
    }

    private MultiIssuerJwtDecoder decoder() {
        return new MultiIssuerJwtDecoder(Map.of(
                ISSUER_A, stub(ISSUER_A),
                ISSUER_B, stub(ISSUER_B)));
    }

    private String token(String issuer) {
        return tokens.firmar(issuer, null, Map.of(), Instant.now().plusSeconds(60));
    }

    @Test
    void enrutaCadaTokenAlDecoderDeSuEmisor() {
        MultiIssuerJwtDecoder decoder = decoder();

        assertThatThrownBy(() -> decoder.decode(token(ISSUER_A)))
                .hasMessageContaining(ISSUER_A);
        assertThatThrownBy(() -> decoder.decode(token(ISSUER_B)))
                .hasMessageContaining(ISSUER_B);
    }

    @Test
    void rechazaUnEmisorQueNoEstaRegistrado() {
        assertThatThrownBy(() -> decoder().decode(token("https://atacante.example.com")))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("no fue emitido por un proveedor registrado");
    }

    @Test
    void rechazaUnTokenQueNoEsUnJwt() {
        assertThatThrownBy(() -> decoder().decode("no-soy-un-jwt"))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("no es un JWT valido");
    }

    @Test
    void rechazaUnTokenSinClaimIss() {
        assertThatThrownBy(() -> decoder().decode(token(null)))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("no contiene un claim iss valido");
    }

    @Test
    void rechazaUnClaimIssQueNoSeaTexto() {
        // La RFC 7519 obliga a que "iss" sea un String. Aceptar una lista dejaria
        // pasar un token que el validador delegado no sabe interpretar.
        String token = tokens.firmarConIssEnLista(List.of(ISSUER_A));

        assertThatThrownBy(() -> decoder().decode(token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("no contiene un claim iss valido");
    }

    @Test
    void elDecoderRealNoSeInvocaParaUnTokenDeEmisorDesconocido() {
        // El token se lee sin verificar la firma solo para elegir decoder, asi que
        // ante un "iss" desconocido ni siquiera debe intentarse la decodificacion.
        JwtDecoder queNuncaDeberiaCorrer = token -> {
            throw new AssertionError("no deberia validar la firma de un emisor desconocido");
        };
        MultiIssuerJwtDecoder decoder = new MultiIssuerJwtDecoder(Map.of(ISSUER_A, queNuncaDeberiaCorrer));

        assertThatThrownBy(() -> decoder.decode(token("https://atacante.example.com")))
                .isInstanceOf(JwtException.class);
    }
}
