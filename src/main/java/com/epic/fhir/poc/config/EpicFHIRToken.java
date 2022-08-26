/*
package com.epic.fhir.poc.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.apache.tomcat.util.net.jsse.PEMFile;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;

@Component
public class EpicFHIRToken {
    public EpicFHIRToken(@Value("classpath:privatekey.pem")
                         Resource privateKeyFile, @Value("classpath:publickey509.pem")
                         Resource publicKeyFile) throws GeneralSecurityException, IOException {
        RSAKey privateKey = (RSAKey) new PEMFile(privateKeyFile.getFile().getName()).getPrivateKey();
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "9acf2bb9-9452-4ae8-841f-820e318a2702");
            claims.put("client_id", "9acf2bb9-9452-4ae8-841f-820e318a2702");
            claims.put("jti", System.currentTimeMillis());
            claims.put("iss", "9acf2bb9-9452-4ae8-841f-820e318a2702");
            claims.put(
                    "aud",
                    "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token");
            Map<String, Object> headers = new HashMap<>();
            headers.put("typ", "JWT");
            headers.put("alg", "RS256");


            Algorithm algorithm = Algorithm.RSA256(privateKey);
            String token = JWT.create()
                    .withClaim("sub", "9acf2bb9-9452-4ae8-841f-820e318a2702")
                    .withClaim("client_id", "9acf2bb9-9452-4ae8-841f-820e318a2702")
            .withClaim("jti", System.currentTimeMillis())
            .withClaim("iss", "9acf2bb9-9452-4ae8-841f-820e318a2702")
            .withClaim(
                    "aud",
                    "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token")
                    .withHeader(headers)
                    .sign(algorithm);
            System.out.println(token);
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }
}
*/
