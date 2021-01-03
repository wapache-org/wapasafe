
# wapasafe - The Wapache Security Project

开发初期的目的是为了给 wapadoc (The Wapache OpenAPI Project) 提供N种认证服务， 以方便演示 OpenAPI V3 的各种安全认证机制。

由于只是一个配套服务，所以可能不会更新很频繁，但是长远来说还是期望这个项目能发展成为一个包含跟安全有关的主流技术的实现集。

## OAuth 2.0

在`docs/oauth`目录下有更多关于OAuth的文档和资料。

### [基于Java实现的OAuth库](https://oauth.net/code/java/)

以下是从[OAuth官方网站](https://oauth.net)找到的用于构建OAuth服务端和客户端的Java开发库。

#### 客户端库

- [Spring Social](https://spring.io/projects/spring-social/)
- [Spring Security](https://spring.io/projects/spring-security/)
- [Restlet Framework (draft 30)](http://www.restlet.org/)
- [ScribeJava](https://github.com/scribejava/scribejava)
- [oauth2-essentials](https://github.com/dmfs/oauth2-essentials)
- [Light Java Client](https://github.com/networknt/light-java/tree/master/client)
- [Google OAuth Java Client](https://github.com/google/google-oauth-java-client)
- [Pac4j](https://www.pac4j.org/)
- [Nimbus](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk)

#### 服务端库

- [MitreID (with OpenID Connect)](https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server)
- [Apis Authorization Server (v2-31)](https://github.com/OpenConextApps/apis)
- [Restlet Framework (draft 30)](http://www.restlet.org/)
- [Apache CXF](https://cxf.apache.org/)
- [Tokens](https://github.com/zalando/tokens): Java library for conveniently verifying and storing OAuth 2.0 service access tokens.
- [Light OAuth2 - The fastest, lightest and cloud native OAuth 2.0 microservices](https://github.com/networknt/light-oauth2)
- [Pac4j](https://www.pac4j.org/)
- [Keycloak](https://www.keycloak.org/)
- [Nimbus](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk)


### [Apache Oltu](https://attic.apache.org/projects/oltu.html) 

Apache Oltu 是一个 OAuth 开源框架，但是很不幸，因不活跃已宣布退休。

wapasafe 的 OAuth 是基于 Apache Oltu 代码改造而成的，目前正在为将servlet api依赖剥离做工作，以支持更多的开发框架，例如Vert.x。

# 贡献代码

欢迎PR\^_\^, hahahaha

