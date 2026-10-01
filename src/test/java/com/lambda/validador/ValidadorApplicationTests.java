package com.lambda.validador;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.messaging.Message;

import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import com.lambda.validador.authorizer.AuthorizerResult;
import com.lambda.validador.security.JwtProviderProperties;
import com.lambda.validador.security.JwtValidationService;

import tools.jackson.databind.ObjectMapper;

/**
 * El contexto de Spring debe levantar sin servidor web, con el bean de la funcion
 * de authorizer disponible y con la respuesta serializada bajo la clave exacta
 * que espera API Gateway.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class ValidadorApplicationTests {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private JwtValidationService validator;

    @Autowired
    private JwtProviderProperties propiedades;

    @Test
    void elContextoArranca() {
        assertThat(context).isNotNull();
        assertThat(validator).isNotNull();
    }

    @Test
    void laFuncionDeAuthorizerQuedaRegistradaComoBean() {
        assertThat(context.getBean("jwtAuthorizer"))
                .isInstanceOf(Function.class);
    }

    @Test
    void laRespuestaSeSerializaConLaClaveIsAuthorized() throws Exception {
        AuthorizerResult permitido = AuthorizerResult.allowed();
        AuthorizerResult denegado = AuthorizerResult.denied();

        // Se usa el mismo mapper que Spring Cloud Function usara en Lambda.
        ObjectMapper mapper = context.getBean(ObjectMapper.class);

        // Ni "context" ni ningun claim: el backend vuelve a validar el token.
        assertThat(mapper.writeValueAsString(permitido)).isEqualTo("{\"isAuthorized\":true}");
        assertThat(mapper.writeValueAsString(denegado)).isEqualTo("{\"isAuthorized\":false}");
    }

    @Test
    void laFirmaDelBeanEsLaDelEventoDelAuthorizer() {
        @SuppressWarnings("unchecked")
        Function<APIGatewayV2CustomAuthorizerEvent, AuthorizerResult> function =
                (Function<APIGatewayV2CustomAuthorizerEvent, AuthorizerResult>)
                        context.getBean("jwtAuthorizer");

        assertThat(function).isNotNull();
    }

    @Test
    void losProveedoresDelYamlSeCargan() {
        // El JWK Set no se descarga al arrancar: la llamada es perezosa y ocurre
        // en la primera peticion real.
        assertThat(propiedades.getProviders())
                .extracting(JwtProviderProperties.Provider::getName)
                .containsExactly("azure", "cognito");
    }
}
