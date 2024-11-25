package org.example.jwt.prop;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

// application.properties 에서 Secret Key를 가져옴
@Data
@Component
@ConfigurationProperties("org.example.jwt")
public class JwtProp {

    // org.example.jwt.secret-key ->(인코딩)-> secretKey
    private String secretKey;
}
