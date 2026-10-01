package com.lambda.validador.support;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import com.sun.net.httpserver.HttpServer;

/**
 * Servidor minimo que sirve un JWK Set en 127.0.0.1 y en un puerto efimero.
 *
 * <p>Existe para que NimbusJwtDecoder ejercite de verdad la descarga de las
 * llaves publicas (lo mismo que hara contra Entra ID o Cognito en produccion)
 * sin que la suite dependa de la red: la URL del decoder apunta siempre a este
 * proceso.</p>
 *
 * <p>Se construye unicamente a traves de {@link TestTokens#publicarJwks(String)},
 * que es quien genera el par de llaves.</p>
 */
public final class JwksServer implements AutoCloseable {

    private final HttpServer server;

    private JwksServer(HttpServer server) {
        this.server = server;
    }

    /** Publica el JWK Set en un puerto efimero y devuelve el servidor. */
    static JwksServer publicar(String jwksJson) {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);

            server.createContext("/.well-known/jwks.json", exchange -> {
                byte[] cuerpo = jwksJson.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, cuerpo.length);
                try (OutputStream salida = exchange.getResponseBody()) {
                    salida.write(cuerpo);
                }
            });

            server.start();
            return new JwksServer(server);
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo levantar el servidor del JWK Set", e);
        }
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/.well-known/jwks.json";
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
