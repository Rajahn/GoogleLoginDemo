# Google Login Demo

这是一个使用Spring Boot + sa-token 实现谷歌账号一键登录的演示项目。

## 功能

- 使用Google OAuth实现一键登录
- 使用sa-token处理登录会话
- 登录后可获取用户信息
- 支持登出功能

## 相关技术

- Spring Boot 2.3.5
- sa-token 1.37.0
- Google API Client 2.3.0
- HTML/JavaScript前端

## 如何使用

1. 克隆项目
2. 修改 `application.properties` 中的 `google.client.id` 为你自己的Google OAuth Client ID
3. 运行应用程序：`mvn spring-boot:run`
4. 访问 `http://localhost:8080` 进行测试

## API接口

- `POST /auth/google-login`: 处理Google登录，需要提供Google返回的token
- `GET /auth/logout`: 登出当前用户
- `GET /user/info`: 获取当前登录用户信息
- `GET /user/isLogin`: 检查当前用户是否已登录

## 注意事项

1. 需要在Google Cloud Console创建项目并配置OAuth 2.0客户端ID
2. 在Google OAuth配置中，需要将`http://localhost:8080`添加到授权的JavaScript来源中
3. 本示例是基础实现，生产环境中需要添加更多的安全措施和错误处理 