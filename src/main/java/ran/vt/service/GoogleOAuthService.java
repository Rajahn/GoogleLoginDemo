package ran.vt.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ran.vt.config.GoogleOAuthConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.api.client.auth.oauth2.TokenResponseException;

import java.io.IOException;
import java.util.Collections;

@Service
public class GoogleOAuthService {
    private static final Logger logger = LoggerFactory.getLogger(GoogleOAuthService.class);

    @Autowired
    private GoogleOAuthConfig config;

    public String getAuthUrl(String state) {
        return "https://accounts.google.com/o/oauth2/v2/auth?" +
                "client_id=" + config.getClient().getId() +
                "&redirect_uri=" + config.getRedirect().getUri() +
                "&response_type=code" +
                "&scope=email profile" +
                "&state=" + state;
    }

    public GoogleIdToken.Payload verifyToken(String code) throws IOException {
        try {
            logger.info("开始验证token，code: {}", code);
            logger.info("使用配置 - client_id: {}, redirect_uri: {}, client_secret: {}", 
                config.getClient().getId(), 
                config.getRedirect().getUri(),
                config.getClient().getSecret() != null ? "已设置" : "未设置");

            // 使用code获取access_token
            GoogleTokenResponse tokenResponse = new GoogleAuthorizationCodeTokenRequest(
                    new NetHttpTransport(),
                    new GsonFactory(),
                    config.getClient().getId(),
                    config.getClient().getSecret(),
                    code,
                    config.getRedirect().getUri())
                    .execute();

            logger.info("成功获取token响应");

            // 验证ID token
            GoogleIdToken idToken = GoogleIdToken.parse(
                    new GsonFactory(),
                    tokenResponse.getIdToken());

            if (idToken == null) {
                logger.error("Invalid ID token");
                throw new IOException("Invalid ID token");
            }

            // 验证token的发行者
            if (!idToken.verifyIssuer(Collections.singletonList("https://accounts.google.com"))) {
                logger.error("Invalid issuer");
                throw new IOException("Invalid issuer");
            }

            // 验证token的接收者
            if (!idToken.verifyAudience(Collections.singletonList(config.getClient().getId()))) {
                logger.error("Invalid audience");
                throw new IOException("Invalid audience");
            }

            logger.info("Token验证成功");
            return idToken.getPayload();
        } catch (TokenResponseException e) {
            logger.error("Token验证失败 - 错误详情: {}", e.getDetails());
            logger.error("Token验证失败 - 错误代码: {}", e.getStatusCode());
            logger.error("Token验证失败 - 错误消息: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Token验证失败", e);
            throw e;
        }
    }
} 