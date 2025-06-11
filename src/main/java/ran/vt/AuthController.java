package ran.vt;

import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import ran.vt.config.GoogleOAuthConfig;
import ran.vt.model.User;
import ran.vt.service.GoogleOAuthService;
import ran.vt.service.UserService;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private GoogleOAuthService googleOAuthService;

    @Autowired
    private UserService userService;

    @Autowired
    private GoogleOAuthConfig config;

    @GetMapping("/google-auth-url")
    public SaResult getGoogleAuthUrl(HttpSession session) {
        // 生成state
        String state = UUID.randomUUID().toString();
        // 存储state到session
        session.setAttribute("oauth_state", state);
        
        // 获取认证URL
        String authUrl = googleOAuthService.getAuthUrl(state);
        return SaResult.ok().setData(authUrl);
    }

    @GetMapping("/google-callback")
    public void handleGoogleCallback(
            @RequestParam String code,
            @RequestParam String state,
            HttpSession session,
            HttpServletResponse response) throws IOException {
        
        // 验证state
        String savedState = (String) session.getAttribute("oauth_state");
        if (savedState == null || !savedState.equals(state)) {
            response.sendRedirect(config.getFrontend().getUrl() + "?error=invalid_state");
            return;
        }
        // 清除state
        session.removeAttribute("oauth_state");

        try {
            // 验证token并获取用户信息
            GoogleIdToken.Payload payload = googleOAuthService.verifyToken(code);
            
            // 提取用户信息
            String email = payload.getEmail();
            String name = (String) payload.get("name");
            String googleId = payload.getSubject();

            // 查找或创建用户
            User user = userService.findOrCreateByEmail(email, name, googleId);

            // 登录
            StpUtil.login(user.getId());

            // 重定向到前端
            response.sendRedirect(config.getFrontend().getUrl() + "?token=" + StpUtil.getTokenValue());
        } catch (Exception e) {
            response.sendRedirect(config.getFrontend().getUrl() + "?error=" + e.getMessage());
        }
    }

    @GetMapping("/logout")
    public SaResult logout() {
        StpUtil.logout();
        return SaResult.ok("注销成功");
    }
}
