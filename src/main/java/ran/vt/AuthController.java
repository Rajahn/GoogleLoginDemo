package ran.vt;

import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ran.vt.model.User;
import ran.vt.service.UserService;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Value("${google.client.id}")
    private String googleClientId;

    @Autowired
    private UserService userService;

    @PostMapping("/google-login")
    public SaResult googleLogin(@RequestBody Map<String, String> body) {
        String idToken = body.get("token");
        GoogleIdToken.Payload payload = verifyGoogleToken(idToken);

        if (payload == null) {
            return SaResult.error("Invalid Google token");
        }

        // 提取用户信息
        String email = payload.getEmail();
        String name = (String) payload.get("name");
        String googleId = payload.getSubject(); // Google用户的唯一ID

        // 查库，如果用户不存在就注册
        User user = userService.findOrCreateByEmail(email, name, googleId);

        // 登录并生成 token
        StpUtil.login(user.getId());

        // 返回给前端 token
        return SaResult.ok("登录成功").setData(StpUtil.getTokenInfo());
    }
    
    @GetMapping("/logout")
    public SaResult logout() {
        StpUtil.logout();
        return SaResult.ok("注销成功");
    }

    private GoogleIdToken.Payload verifyGoogleToken(String idTokenString) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);
            return idToken != null ? idToken.getPayload() : null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
