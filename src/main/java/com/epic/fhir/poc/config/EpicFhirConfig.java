package com.epic.fhir.poc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.DataInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class EpicFhirConfig {

    public EpicFhirConfig( @Value("classpath:privatekeypkcs.der")
    Resource publicKey){
        getJWT( publicKey);
    }
    @SneakyThrows
    public void getJWT(Resource publicKey) {

        InputStream stream = publicKey.getInputStream();
        byte[] keyBytes;
        try (DataInputStream dis = new DataInputStream(stream)) {
            keyBytes = new byte[stream.available()];
            dis.readFully(keyBytes);
        }
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "9acf2bb9-9452-4ae8-841f-820e318a2702");
        claims.put("client_id", "9acf2bb9-9452-4ae8-841f-820e318a2702");
        claims.put("jti", System.currentTimeMillis());
        claims.put("iss", "9acf2bb9-9452-4ae8-841f-820e318a2702");
        claims.put(
                "aud",
                "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token");
        claims.put("exp", (System.currentTimeMillis()/1000)+240);

        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        headers.put("alg", "RS256");
        ObjectMapper objectMapper = new ObjectMapper();
        PKCS8EncodedKeySpec x509EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(x509EncodedKeySpec);
        String token = Jwts.builder()
                .setPayload(objectMapper.writeValueAsString(claims))
                .setHeader(headers)
                .signWith(key)
                .compact();
        System.out.println("JWT: "+token);
        System.out.println("**********************");
        System.out.println("Access Token: "+fetchToken(token));
        System.out.println("**********************");
    }


   private String fetchToken(String jwt) {
        RestTemplate template = new RestTemplate();
        String tokenUrl =
                "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token";
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        MultiValueMap<String, String> bodyMap = new LinkedMultiValueMap<>();
//        bodyMap.add("scope", "system/*.*");
        bodyMap.add("grant_type", "client_credentials");
        bodyMap.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        bodyMap.add("client_assertion", jwt);
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(bodyMap, headers);
        Map response = template.postForObject(tokenUrl, requestEntity, Map.class);
        if (null == response) return null;
        return (String) response.getOrDefault("access_token", null);
    }
}
