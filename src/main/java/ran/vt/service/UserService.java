package ran.vt.service;

import org.springframework.stereotype.Service;
import ran.vt.model.User;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class UserService {
    // 简单模拟数据库存储
    private final Map<String, User> userByEmail = new ConcurrentHashMap<>();
    private final AtomicLong idGenerator = new AtomicLong(1);

    /**
     * 根据邮箱查找用户，不存在则创建
     */
    public User findOrCreateByEmail(String email, String name, String googleId) {
        return userByEmail.computeIfAbsent(email, k -> {
            User user = new User();
            user.setId(idGenerator.getAndIncrement());
            user.setEmail(email);
            user.setName(name);
            user.setGoogleId(googleId);
            return user;
        });
    }

    /**
     * 根据ID查找用户
     */
    public User findById(Long id) {
        return userByEmail.values().stream()
                .filter(user -> user.getId().equals(id))
                .findFirst()
                .orElse(null);
    }
} 