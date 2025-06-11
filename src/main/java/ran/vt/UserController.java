package ran.vt;

import cn.dev33.satoken.annotation.SaCheckLogin;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ran.vt.model.User;
import ran.vt.service.UserService;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @SaCheckLogin
    @GetMapping("/info")
    public SaResult getUserInfo() {
        // 获取当前登录用户ID
        Long userId = StpUtil.getLoginIdAsLong();
        // 查询用户信息
        User user = userService.findById(userId);
        
        if (user == null) {
            return SaResult.error("用户不存在");
        }
        
        return SaResult.ok().setData(user);
    }
    
    @GetMapping("/isLogin")
    public SaResult isLogin() {
        return SaResult.ok("是否登录：" + StpUtil.isLogin());
    }
} 