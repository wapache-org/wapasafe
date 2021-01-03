
# [Implementing The OAuth 2.0 Authorization Framework Using Jakarta EE](https://www.baeldung.com/java-ee-oauth2-implementation)

代码仓库地址: https://github.com/eugenp/tutorials/tree/master/oauth2-framework-impl

## 读书笔记

本文各种角色、授权流程、接口对应关系：

| 顺序  | 角色                                                      | 接口            | 说明                                                         |
| ----- | --------------------------------------------------------- | --------------- | ------------------------------------------------------------ |
|       | 用户                                                      |                 | **一般就是指人咯**                                           |
|       | 浏览器/手机APP                                            |                 | **跟`用户`交互的渠道/图形界面**<br />这是整个OAuth授权流程中, 用户惟一能接触到的部分。 |
| 1,5,7 |                                                           | 打开网页或APP   |                                                              |
|       | OAuth2 Client<br />(http://localhost:9180/)               |                 | **给`用户`提供服务的手机APP或网站的后台服务器**<br />如果没有后台服务, 那么手机APP/浏览器兼任了这个角色。 |
| 2     |                                                           | /authorize      | 供`用户`登录或者选择OAuth2授权提供方                         |
| 8     |                                                           | /callback       | 供`Authoization Server`回调, 把授权码传给`Client`            |
|       | OAuth2 Authoization Server<br /> (http://localhost:9080/) |                 | **某些知名的互联网公司提供的OAuth 2.0 授权服务器**           |
| 0     |                                                           | /register       | 供`用户`和`Client`注册                                       |
| 3,4,6 |                                                           | /authorize      | 供`Client`申请`用户`的授权码, 供`用户`登录, 供`用户`选择是否授权 |
| 9     |                                                           | /token          | 供`Client`获取`用户资源`的访问令牌                           |
|       | OAuth2 Resource Server<br />(http://localhost:9280/)      |                 | **该互联网公司用来存储`用户`的数据的服务器**                 |
| 10    |                                                           | /resource/read  | 读取`用户`资源                                               |
| 10    |                                                           | /resource/write | 修改`用户`资源                                               |


以下开始是原文内容和对应翻译。


## **1. Overview**



In this tutorial, we're going to provide an implementation for the [OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) using Jakarta EE And MicroProfile. Most importantly, we're going to implement the interaction of the [OAuth 2.0 roles](https://tools.ietf.org/html/rfc6749#page-6) through the [Authorization Code grant type](https://tools.ietf.org/html/rfc6749#page-24). The motivation behind this writing is to give support for projects that are implemented using Jakarta EE as this doesn't yet provide support  for OAuth.

For the most important role, the Authorization Server, **we're going to implement the Authorization Endpoint, the Token Endpoint and additionally, the JWK Key Endpoint**, which is useful for the Resource Server to retrieve the public key.



As we want the implementation to be simple and easy for a quick  setup, we're going to use a pre-registered store of clients and users,  and obviously a JWT store for access tokens.

**Before jumping right into the topic, it's important to note  that the example in this tutorial is for educational purposes. For  production systems, it's highly recommended to use a mature, well-tested solution such as [Keycloak](https://www.baeldung.com/spring-boot-keycloak).**



在本教程中，我们将提供一个使用Jakarta EE和MicroProfile的 [OAuth 2.0授权框架](https://tools.ietf.org/html/rfc6749) 的实现。最重要的是，我们将通过 [授权码授予类型](https://tools.ietf.org/html/rfc6749#page-24) 实现 [OAuth 2.0角色](https://tools.ietf.org/html/rfc6749#page-6) 的交互。这样写的动机是为了给使用Jakarta EE实现的项目提供支持，因为这个还没有提供对OAuth的支持。

对于最重要的角色--授权服务器，**我们要实现授权端点、Token端点，另外还要实现JWK密钥端点**，这对资源服务器检索公钥很有用。



由于我们希望实现简单易行，以便快速设置，我们将使用一个预先注册的客户端和用户的存储，显然还有一个JWT存储用于访问令牌。

**在直接进入主题之前，需要注意的是，本教程中的例子是用于教育目的。对于生产系统，强烈建议使用成熟的、经过良好测试的解决方案，如 [Keycloak](https://www.baeldung.com/spring-boot-keycloak) .**。







## 2. OAuth 2.0 Overview



In this section, we're going to give a brief overview of the OAuth 2.0 roles and the Authorization Code grant flow.

在本节中，我们将对OAuth 2.0的角色和授权码授予流程进行简要介绍。



### 2.1. Roles

### 

The OAuth 2.0 framework implies the collaboration between the four following roles:

- *Resource Owner*: Usually, this is the end-user – it's the entity that has some resources worth protecting
- *Resource Server*: An service that protects the resource owner's data, usually publishing it through a REST API
- *Client*: An application that uses the resource owner's data
- *Authorization Server*: An application that grants permission – or authority – to clients in the form of expiring tokens



OAuth 2.0框架意味着以下四个角色之间的合作。

- *资源所有者*。通常，这就是最终用户--它是拥有一些值得保护的资源的实体。
- *资源服务器*。保护资源所有者数据的服务，通常通过REST API发布。
- *客户端*。使用资源所有者数据的应用程序。
- *授权服务器*。以`有期限的访问令牌`形式向客户发放许可或授权的应用程序。



### 2.2. Authorization Grant Types

### 

A *grant type* is how a client gets permission to use the resource owner's data, ultimately in the form of an access token.

Naturally, different types of clients [prefer different types of grants](https://oauth2.thephpleague.com/authorization-server/which-grant/):

- *Authorization Code*: **Preferred most often** *–* whether it is **a web application, a native application, or a single-page application**, though native and single-page apps require additional protection called PKCE
- *Refresh Token*: A special renewal grant, **suitable for web applications** to renew their existing token
- *Client Credentials*: Preferred for **service-to-service communication**, say when the resource owner isn't an end-user
- *Resource Owner* *Password*: Preferred for the **first-party authentication of native applications\*,\*** say when the mobile app needs its own login page

In addition, the client can use the *implicit* grant type. However, it's usually more secure to use the authorization code grant with PKCE.



授权类型是指`客户端`如何获得使用`资源所有者`数据的权限，最终以`访问令牌`的形式出现。

当然，不同类型的客户端[喜欢不同类型的授权](https://oauth2.thephpleague.com/authorization-server/which-grant/)。

- *授权码*。**无论**是网络应用、原生应用还是单页应用，**最喜欢**，不过原生应用和单页应用需要额外的保护，称为PKCE
- *刷新令牌*。一种特别的更新授权，**适合网络应用**，以更新其现有的令牌。
- *客户端凭证*。**服务对服务通信**的首选，例如当资源所有者不是最终用户时。
- *资源所有者* *密码*。首选用于**本地应用程序的第一方认证**，比如当移动应用程序需要自己的登录页面时。

此外，客户端还可以使用隐式的授权类型。但是，通常使用PKCE的授权码授予更安全。



### 2.3. Authorization Code Grant Flow

### 

Since the authorization code grant flow is the most common, let's also review how that works, and **that's actually what we'll build in this tutorial.**

An application – a client – **requests permission by redirecting to the authorization server's \*/authorize\* endpoint.** To this endpoint, the application gives a *callback* endpoint.



The authorization server will usually ask the end-user – the resource owner – for permission. If the end-user grants permission, then **the authorization server redirects back to the callback** with a *code*.

The application receives this code and then **makes an authenticated call to the authorization server's \*/token\* endpoint.** By “authenticated”, we mean that the application proves who it is as part  of this call. If all appears in order, the authorization server responds with the token.

With the token in hand, **the application makes its request to the API** – the resource server – and that API will verify the token. It can ask the authorization server to verify the token using its */introspect* endpoint. Or, if the token is self-contained, the resource server can optimize by **locally verifying the token's signature, as is the case with JWT.**



由于授权代码授予流程是最常见的，所以我们也来回顾一下它是如何工作的，**这实际上就是我们在本教程中要构建的**。

1. 一个应用程序--客户端--**通过重定向到授权服务器的 \*/authorize\* 端点来请求权限.**对这个端点，应用程序给出了一个*回调*端点。

2. 授权服务器通常会询问终端用户--资源所有者--是否允许。如果最终用户授予权限，那么**授权服务器就会携带一个*code*重定向到回调地址**。

3. 应用程序接收到这个code，然后**对授权服务器的 \*/token\* 端点进行认证调用。**所说的 "认证 "是指应用程序证明自己是谁，作为这次调用的一部分。如果一切正常，授权服务器就会颁发一个令牌进行响应。

4. 拿到令牌后，**应用程序向API**--资源服务器--发出请求，该API将验证令牌。它可以要求授权服务器使用其*/introspect*端点来验证令牌。或者，如果令牌是自包含的，资源服务器可以通过**本地验证令牌的签名进行优化，就像JWT的情况一样**。





### 2.4. What Does Jakarta EE Support?

### 

Not much, yet. In this tutorial, we'll build most things from the ground up.

暂时还不多。在本教程中，我们将从头开始构建大部分东西。



## 3. OAuth 2.0 Authorization Server

In this implementation, we'll focus on **the most commonly used grant type**: Authorization Code.

在本实现中，我们将重点介绍**最常用的授权类型**: 授权码授权。



### 3.1. Client and User Registration



An authorization server would, of course, need to know about the  clients and users before it can authorize their requests. And it's  common for an authorization server to have a UI for this.

For simplicity, though, we'll use a pre-configured client:

当然，一个授权服务器在授权客户端和用户的请求之前，需要了解客户端和用户的情况。而授权服务器通常会有一个用户界面来处理这个问题。

不过为了简单起见，我们将使用一个预先配置的客户端。



```sql
INSERT INTO clients (client_id, client_secret, redirect_uri, scope, authorized_grant_types) 
VALUES ('webappclient', 'webappclientsecret', 'http://localhost:9180/callback', 
  'resource.read resource.write', 'authorization_code refresh_token');

```



```java
@Entity
@Table(name = "clients")
public class Client {
    
    @Id
    @Column(name = "client_id")
    private String clientId;
    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "redirect_uri")
    private String redirectUri;

    @Column(name = "scope")
    private String scope;

    // ...
}
```



And a pre-configured user:

和一个预先配置好的用户:

```java
@Entity
@Table(name = "users")
public class User implements Principal {
    @Id
    @Column(name = "user_id")
    private String userId;

    @Column(name = "password")
    private String password;

    @Column(name = "roles")
    private String roles;

    @Column(name = "scopes")
    private String scopes;

    // ...
}
```



```sql
INSERT INTO users (user_id, password, roles, scopes)
VALUES ('appuser', 'appusersecret', 'USER', 'resource.read resource.write');
```



Note that for the sake of this tutorial, we've used passwords in plain text, **but in a production environment, they should be hashed**.

For the rest of this tutorial, we'll show how *appuser –* the resource owner – can grant access to *webappclient* – the application – by implementing the Authorization Code.



请注意，在本教程中，我们使用了纯文本的密码，**但在生产环境中，它们应该被哈希**。

在本教程的其余部分，我们将展示*appuser* - 资源所有者如何通过`授权码授权`来授予*webappclient - 应用程序访问权。



### 3.2. Authorization Endpoint



The main role of the authorization endpoint is to first **authenticate the user and then ask for the permissions** – or scopes – that the application wants.

As [instructed by the OAuth2 specs](https://tools.ietf.org/html/rfc6749#section-3.1), this endpoint should support the HTTP GET method, although it can also  support the HTTP POST method. In this implementation, we'll support only the HTTP GET method.

First, **the authorization endpoint requires that the user be authenticated**. The spec doesn't require a certain way here, so let's use Form Authentication from the [Jakarta EE 8 Security API](https://www.baeldung.com/java-ee-8-security):



授权端点的主要作用是首先**认证用户，然后请求应用程序想要的权限或作用域**。

按照[OAuth2规范的指示](https://tools.ietf.org/html/rfc6749#section-3.1)，这个端点应该支持HTTP GET方法，尽管它也可以支持HTTP POST方法。在这个实现中，我们将只支持HTTP GET方法。

首先，**授权端点需要对用户进行认证**。规范在这里并没有要求一定的方式，所以我们使用[Jakarta EE 8 Security API](https://www.baeldung.com/java-ee-8-security)中的`表单认证`。



```java
@FormAuthenticationMechanismDefinition(
  loginToContinue = @LoginToContinue(loginPage = "/login.jsp", errorPage = "/login.jsp")
)
```

The user will be redirected to */login.jsp* for authentication and then will be available as a *CallerPrincipal* through the S*ecurityContext* API:

用户将被重定向到*/login.jsp*进行认证，然后通过S*ecurityContext* API的*CallerPrincipal*获得用户身份信息。

```java
Principal principal = securityContext.getCallerPrincipal();
```

We can put these together using JAX-RS:



```java
@FormAuthenticationMechanismDefinition(
  loginToContinue = @LoginToContinue(loginPage = "/login.jsp", errorPage = "/login.jsp")
)
@Path("authorize")
public class AuthorizationEndpoint {
    //...    
    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response doGet(
        @Context HttpServletRequest request,
        @Context HttpServletResponse response,
        @Context UriInfo uriInfo
    ) throws ServletException, IOException {
        
        MultivaluedMap<String, String> params = uriInfo.getQueryParameters();
        Principal principal = securityContext.getCallerPrincipal();
        // ...
    }
}
```



At this point, the authorization endpoint can start processing the application's request, which must contain ***response_type\* and \*client_id\* parameters and – optionally, but recommended – the \*redirect_uri, scope,\* and \*state\* parameters.**

The *client_id* should be a valid client, in our case from the *clients* database table.

The *redirect_uri*, if specified, should also match what we find in the *clients* database table.

And, because we're doing Authorization Code, *response_type* is *code.* 

Since authorization is a multi-step process, we can temporarily store these values in the session:



现在，授权端点可以开始处理应用程序的请求了，其中必须包含**\*response_type\*和\*client_id\*参数，以及-可选但推荐的-\*redirect_uri、scope、\*和\*state\*参数**。

*client_id*应该是一个有效的客户端，在我们的例子中，来自*clients*数据库表。

如果指定了*redirect_uri*，也应该与我们在*clients*数据库表中找到的匹配。

而且，因为我们使用的流程是授权码授权，所以*response_type*是*code.*。

因为授权是一个多步骤的过程，所以我们可以将这些值暂时存储在session中。



```java
request.getSession().setAttribute("ORIGINAL_PARAMS", params);
```

And then prepare to ask the user which permissions the application may use, redirecting to that page:

然后准备询问用户该应用可以使用哪些权限，重定向到该页面。

```java
String allowedScopes = checkUserScopes(user.getScopes(), requestedScope);
request.setAttribute("scopes", allowedScopes);
request.getRequestDispatcher("/authorize.jsp").forward(request, response);
```



### 3.3. User Scopes Approval



At this point, the browser renders an authorization UI for the user, and **the user makes a selection.** Then, the browser **submits the user's selection in** **an HTTP POST**:

此时，浏览器为用户渲染一个授权UI，**用户进行选择，**然后，浏览器提交用户的选择，**一个HTTP POST**。

```java
@POST
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
@Produces(MediaType.TEXT_HTML)
public Response doPost(@Context HttpServletRequest request, @Context HttpServletResponse response,
  MultivaluedMap<String, String> params) throws Exception {
    MultivaluedMap<String, String> originalParams = 
      (MultivaluedMap<String, String>) request.getSession().getAttribute("ORIGINAL_PARAMS");

    // ...

    String approvalStatus = params.getFirst("approval_status"); // YES OR NO

    // ... if YES

    List<String> approvedScopes = params.get("scope");

    // ...
}
```

Next, we generate a temporary code that refers to the ***user_id, client_id,\* and** ***redirect_uri,\*** all of which the application will use later when it hits the token endpoint.

So let's create an *AuthorizationCode* JPA Entity with an auto-generated id*:*

接下来，我们生成一个临时代码，引用**\*user_id,client_id,\*和\*redirect_uri,\***，所有这些代码都是应用程序稍后在点击token端点时需要用到的。

因此，让我们创建一个具有自动生成ID的*AuthorizationCode* JPA实体。

```java
@Entity
@Table(name ="authorization_code")
public class AuthorizationCode {
@Id
@GeneratedValue(strategy=GenerationType.AUTO)
@Column(name = "code")
private String code;

//...

}
```

And then populate it:

```java
AuthorizationCode authorizationCode = new AuthorizationCode();
authorizationCode.setClientId(clientId);
authorizationCode.setUserId(userId);
authorizationCode.setApprovedScopes(String.join(" ", authorizedScopes));
authorizationCode.setExpirationDate(LocalDateTime.now().plusMinutes(2));
authorizationCode.setRedirectUri(redirectUri);
```

When we save the bean, the code attribute is auto-populated, and so we can get it and send it back to the client:

当我们保存bean的时候，代码属性是自动填充的，这样我们就可以得到它，然后再发回给客户端。

```java
appDataRepository.save(authorizationCode);
String code = authorizationCode.getCode();
```

Note that **our authorization code will expire in two minutes** – we should be as conservative as we can with this expiration. It can  be short since the client is going to exchange it right away for an  access token.

We then redirect back to the application's *redirect_uri,* giving it the code as well as any *state* parameter that the application specified in its */authorize* request:

请注意，**我们的授权码将在两分钟后过期** - 对于这个过期时间我们应该尽可能地保守。它可以很短，因为客户端会马上将它换成访问令牌。

然后我们重定向回应用程序的*redirect_uri，*给它代码以及应用程序在*/authorize*请求中指定的任何*状态*参数。

```java
StringBuilder sb = new StringBuilder(redirectUri);
// ...

sb.append("?code=").append(code);
String state = params.getFirst("state");
if (state != null) {
    sb.append("&state=").append(state);
}
URI location = UriBuilder.fromUri(sb.toString()).build();
return Response.seeOther(location).build();
```

Note again that ***redirectUri\* is whatever exists in the \*clients\* table, not the \*redirect_uri\* request parameter.**

So, our next step is for the client to receive this code and exchange it for an access token using the token endpoint.

请再次注意，**\*redirectUri\*是存在于 \*clients\*表中的任何东西，而不是 \*redirect_uri\*请求参数**。

所以，我们的下一步是让客户端接收这个代码，并使用token端点将其换成一个访问令牌。



### 3.4. Token Endpoint



As opposed to the authorization endpoint, the token endpoint **doesn't need a browser to communicate with the client**, and we'll, therefore, implement it as a JAX-RS endpoint:

与授权端点相比，令牌端点**不需要浏览器与客户端**通信，因此，我们将把它作为一个JAX-RS端点来实现。

```java
@Path("token")
public class TokenEndpoint {

    List<String> supportedGrantTypes = Collections.singletonList("authorization_code");

    @Inject
    private AppDataRepository appDataRepository;

    @Inject
    Instance<AuthorizationGrantTypeHandler> authorizationGrantTypeHandlers;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response token(MultivaluedMap<String, String> params,
       @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader) throws JOSEException {
        //...
    }
}
```

The token endpoint requires a POST, as well as encoding the parameters using the *application/x-www-form-urlencoded* media type.

As we discussed, we'll be supporting only the *authorization code* grant type:

令牌端点需要一个POST，以及使用*application/x-www-form-urlencoded*媒体类型对参数进行编码。

正如我们所讨论的，我们将只支持*授权码*授予类型。

```java
List<String> supportedGrantTypes = Collections.singletonList("authorization_code");
```

So, the received *grant_type* as a required parameter should be supported:

所以，应该支持将接收到的*grant_type*作为必填参数。

```java
String grantType = params.getFirst("grant_type");
Objects.requireNonNull(grantType, "grant_type params is required");
if (!supportedGrantTypes.contains(grantType)) {
    JsonObject error = Json.createObjectBuilder()
      .add("error", "unsupported_grant_type")
      .add("error_description", "grant type should be one of :" + supportedGrantTypes)
      .build();
    return Response.status(Response.Status.BAD_REQUEST)
      .entity(error).build();
}
```

Next, we check the client authentication through via HTTP Basic authentication. That is, we check **if the received \*client_id\* and \*client_secret\****,* through the *Authorization* header, **matches a registered client:**

接下来，我们通过HTTP基本认证来检查客户端认证。也就是说，我们通过*Authorization*头检查**接收到的\*client_id\*和\*client_secret\***,**是否匹配一个注册的客户端：**。

```java
String[] clientCredentials = extract(authHeader);
String clientId = clientCredentials[0];
String clientSecret = clientCredentials[1];
Client client = appDataRepository.getClient(clientId);
if (client == null || clientSecret == null || !clientSecret.equals(client.getClientSecret())) {
    JsonObject error = Json.createObjectBuilder()
      .add("error", "invalid_client")
      .build();
    return Response.status(Response.Status.UNAUTHORIZED)
      .entity(error).build();
}
```

Finally, we delegate the production of the *TokenResponse* to a corresponding grant type handler:

最后，我们将*TokenResponse*的生产委托给相应的授予类型处理程序。

```java
public interface AuthorizationGrantTypeHandler {
    TokenResponse createAccessToken(String clientId, MultivaluedMap<String, String> params) throws Exception;
}
```

As we're more interested in the authorization code grant type, we've  provided an adequate implementation as a CDI bean and decorated it with  the *Named* annotation:

由于我们对授权码授予类型比较感兴趣，所以我们提供了一个充分的实现作为CDI bean，并用*Named*注解来装饰它。

```plaintext
@Named("authorization_code")
```

At runtime, and according to the received *grant_type* value, the corresponding implementation is activated through the [CDI Instance mechanism](https://javaee.github.io/javaee-spec/javadocs/javax/enterprise/inject/Instance.html):

在运行时，并根据接收到的*grant_type*值，通过[CDI实例机制](https://javaee.github.io/javaee-spec/javadocs/javax/enterprise/inject/Instance.html)激活相应的实现。

```java
String grantType = params.getFirst("grant_type");
//...
AuthorizationGrantTypeHandler authorizationGrantTypeHandler = 
  authorizationGrantTypeHandlers.select(NamedLiteral.of(grantType)).get();
```

It's now time to produce */token*‘s response.

接下来就可以生成*/token*的响应了



### 3.5. *RSA* Private and Public Keys



**Before generating the token, we need an RSA private key for signing tokens.**

For this purpose, we'll be using OpenSSL:

**在生成令牌之前，我们需要一个RSA私钥来签署令牌。**

为此，我们将使用OpenSSL。

```bash
# PRIVATE KEY
openssl genpkey -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:2048
```

The *private-key.pem* is provided to the server through the MicroProfile Config *signingKey* property using the file *META-INF/microprofile-config.properties:*

 *private-key.pem*通过MicroProfile Config属性 *signingKey*提供给服务器，使用文件*META-INF/microprofile-config.properties:*

```plaintext
signingkey=/META-INF/private-key.pem
```

The server can read the property using the injected *Config* object:

服务器可以使用注入的*Config*对象读取该属性。

```java
String signingkey = config.getValue("signingkey", String.class);
```

Similarly, we can generate the corresponding public key:

同样，我们也可以生成相应的公钥。

```bash
# PUBLIC KEY
openssl rsa -pubout -in private-key.pem -out public-key.pem
```

And use the MicroProfile Config *verificationKey* to read it:

并使用MicroProfile Config *verificationKey*来读取。

```plaintext
verificationkey=/META-INF/public-key.pem
```

The server should make it available for the resource server for **the purpose of verification.** This is done **through a JWK endpoint.**

**[Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt)** is a library that can be a big help here. Let's first add [the *nimbus-jose-jwt* dependency](https://search.maven.org/search?q=g:com.nimbusds AND a:nimbus-jose-jwt&core=gav):

服务器应该为资源服务器提供，以达到**验证的目的，**通过JWK端点来完成。

**[Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt)**是一个库，在这里可以提供很大的帮助。首先让我们添加[*nimbus-jose-jwt*依赖](https://search.maven.org/search?q=g:com.nimbusds AND a:nimbus-jose-jwt&core=gav)。

```xml
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>7.7</version>
</dependency>
```

And now, we can leverage Nimbus's JWK support to simplify our endpoint:

而现在，我们可以利用Nimbus的JWK支持来简化我们的终端。

```java
@Path("jwk")
@ApplicationScoped
public class JWKEndpoint {

    @GET
    public Response getKey(@QueryParam("format") String format) throws Exception {
        //...

        String verificationkey = config.getValue("verificationkey", String.class);
        String pemEncodedRSAPublicKey = PEMKeyUtils.readKeyAsString(verificationkey);
        if (format == null || format.equals("jwk")) {
            JWK jwk = JWK.parseFromPEMEncodedObjects(pemEncodedRSAPublicKey);
            return Response.ok(jwk.toJSONString()).type(MediaType.APPLICATION_JSON).build();
        } else if (format.equals("pem")) {
            return Response.ok(pemEncodedRSAPublicKey).build();
        }

        //...
    }
}
```

We've used the format *parameter* to switch between the PEM  and JWK formats. The MicroProfile JWT which we'll use for implementing  the resource server supports both these formats.

我们使用格式*参数*在PEM和JWK格式之间切换。我们将用于实现资源服务器的MicroProfile JWT支持这两种格式。

### 3.6. Token Endpoint Response

It's now time for a given *AuthorizationGrantTypeHandler* to create the token response. In this implementation, we'll support only the structured JWT Tokens.

**For creating a token in this format, we'll again use the [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) library**, but there are [numerous other JWT libraries](https://jwt.io/#libraries-io), too.

So, to create a signed JWT, **we first have to construct the JWT header:**

现在是时候给指定的*AuthorizationGrantTypeHandler*创建令牌响应了。在这个实现中，我们将只支持结构化的JWT令牌。

**为了创建这种格式的令牌，我们将再次使用[Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt)库**，但也有[众多其他JWT库](https://jwt.io/#libraries-io)。

所以，要创建一个签名的JWT，**我们首先要构造JWT头**。

```java
JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
```

**Then, we build the payload** which is a *Set* of standardized and custom claims:

**然后，我们建立有效载荷**，这是一套标准的和定制的claims。

```java
Instant now = Instant.now();
Long expiresInMin = 30L;
Date in30Min = Date.from(now.plus(expiresInMin, ChronoUnit.MINUTES));

JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
  .issuer("http://localhost:9080")
  .subject(authorizationCode.getUserId())
  .claim("upn", authorizationCode.getUserId())
  .audience("http://localhost:9280")
  .claim("scope", authorizationCode.getApprovedScopes())
  .claim("groups", Arrays.asList(authorizationCode.getApprovedScopes().split(" ")))
  .expirationTime(in30Min)
  .notBeforeTime(Date.from(now))
  .issueTime(Date.from(now))
  .jwtID(UUID.randomUUID().toString())
  .build();
SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaims);
```

In addition to the standard JWT claims, we've added two more claims – *upn* and *groups* – as they're needed by the MicroProfile JWT. The *upn* will be mapped to the Jakarta EE Security *CallerPrincipal* and the *groups* will be mapped to Jakarta EE *Roles.*

Now that we have the header and the payload, **we need to sign the access token with an RSA private key**. The corresponding RSA public key will be exposed through the JWK  endpoint or made available by other means so that the resource server  can use it to verify the access token.

As we've provided the private key as a PEM format, we should retrieve it and transform it into an *RSAPrivateKey:*

除了标准的JWT要求，我们还增加了两个要求--*upn*和*groups*，因为MicroProfile JWT需要它们。upn*将被映射到Jakarta EE Security *CallerPrincipal*，而*groups*将被映射到Jakarta EE *Roles.*。

现在我们有了头和有效载荷，**我们需要用RSA私钥**签署访问令牌。相应的RSA公钥将通过JWK端点暴露或通过其他方式提供，以便资源服务器可以使用它来验证访问令牌。

由于我们提供的私钥是PEM格式，所以我们应该检索它并将其转化为*RSAP私钥。

```java
SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaims);
//...
String signingkey = config.getValue("signingkey", String.class);
String pemEncodedRSAPrivateKey = PEMKeyUtils.readKeyAsString(signingkey);
RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects(pemEncodedRSAPrivateKey);
```

Next, **we sign and serialize the JWT:**

接下来，**我们对JWT进行签名和序列化：**

```java
signedJWT.sign(new RSASSASigner(rsaKey.toRSAPrivateKey()));
String accessToken = signedJWT.serialize();
```

And finally **we construct a token response:**

最后**我们构造一个令牌响应：**。

```java
return Json.createObjectBuilder()
  .add("token_type", "Bearer")
  .add("access_token", accessToken)
  .add("expires_in", expiresInMin * 60)
  .add("scope", authorizationCode.getApprovedScopes())
  .build();
```

which is, thanks to JSON-P, serialized to JSON format and sent to the client:

由于有JSON-P的支持，它被序列化为JSON格式并发送给客户端。

```javascript
{
  "access_token": "acb6803a48114d9fb4761e403c17f812",
  "token_type": "Bearer",  
  "expires_in": 1800,
  "scope": "resource.read resource.write"
}
```



## 4. OAuth 2.0 Client



In this section, we'll be **building a web-based OAuth 2.0 Client** using the Servlet, MicroProfile Config, and JAX RS Client APIs.

More precisely, we'll be implementing two main servlets: one for  requesting the authorization server's authorization endpoint and getting a code using the authorization code grant type, and another servlet for using the received code and requesting an access token from the  authorization server's token endpoint.

Additionally, we'll be implementing two more servlets: One for  getting a new access token using the refresh token grant type, and  another for accessing the resource server's APIs.



在本节中，我们将**使用Servlet、MicroProfile Config和JAX RS Client API来构建一个基于Web的OAuth 2.0客户端**。

更准确地说，我们将实现两个主要的servlet：一个用于请求授权服务器的授权端点，并使用授权代码授予类型获得代码，另一个servlet用于使用接收到的代码，并从授权服务器的令牌端点请求访问令牌。

此外，我们还将实现两个servlet。一个用于使用刷新令牌授予类型获取新的访问令牌，另一个用于访问资源服务器的API。



1. : 用于请求授权服务器的授权端点，并使用授权代码授予类型获得代码
2. : 用于使用接收到的代码，并从授权服务器的令牌端点请求访问令牌
3. : 用于使用刷新令牌授予类型获取新的访问令牌
4. : 用于访问资源服务器的API。



### 4.1. OAuth 2.0 Client Details



As the client is already registered within the authorization server,  we first need to provide the client registration information:

- *client_id:* Client Identifier and it's usually issued by the authorization server during the registration process.
- *client_secret:* Client Secret.
- *redirect_uri:* Location where to receive the authorization code.
- *scope:* Client requested permissions.

Additionally, the client should know the authorization server's authorization and token endpoints:

- *authorization_uri:* Location of the authorization server authorization endpoint that we can use to get a code.
- *token_uri:* Location of the authorization server token endpoint that we can use to get a token.

All this information is provided through the MicroProfile Config file, *META-INF/microprofile-config.properties:*



由于客户端已经在授权服务器内注册，我们首先需要提供客户端注册信息。

- *client_id:* 客户端标识符，通常由授权服务器在注册过程中发出。
- *client_secret:* 客户端密码，它通常由授权服务器在注册过程中发出。
- redirect_uri: 接收授权码的网址。
- scope: 客户端请求的权限。

此外，客户端应该知道授权服务器的授权和令牌端点。

- 此外，客户端应该知道授权服务器的授权和令牌端点： *authorization_uri:*授权服务器授权端点的位置，我们可以用它来获取代码。
- *token_uri:*我们可以用来获取令牌的授权服务器令牌端点的位置。

所有这些信息都通过MicroProfile Config文件提供，*META-INF/microprofile-config.properties:*。



```plaintext
# Client registration
client.clientId=webappclient
client.clientSecret=webappclientsecret
client.redirectUri=http://localhost:9180/callback
client.scope=resource.read resource.write

# Provider
provider.authorizationUri=http://127.0.0.1:9080/authorize
provider.tokenUri=http://127.0.0.1:9080/token
```

### 4.2. Authorization Code Request



**The flow of getting an authorization code starts with the  client by redirecting the browser to the authorization server's  authorization endpoint.**

Typically, this happens when the user tries to access a protected  resource API without authorization, or by explicitly by invoking the  client */authorize* path:

获取授权代码的流程从客户端开始，将浏览器重定向到授权服务器的授权端点。

通常情况下，当用户试图在没有授权的情况下访问受保护的资源API时，或者通过明确地调用客户端*/authorize*路径，就会发生这种情况。

```java
@WebServlet(urlPatterns = "/authorize")
public class AuthorizationCodeServlet extends HttpServlet {

    @Inject
    private Config config;

    @Override
    protected void doGet(HttpServletRequest request, 
      HttpServletResponse response) throws ServletException, IOException {
        //...
    }
}
```

In the *doGet()* method, we start by generating and storing a security state value:

在*doGet()*方法中，我们首先生成并存储一个安全状态值。

```java
String state = UUID.randomUUID().toString();
request.getSession().setAttribute("CLIENT_LOCAL_STATE", state);
```

Then, we retrieve the client configuration information:

然后，我们检索客户端配置信息。

```java
String authorizationUri = config.getValue("provider.authorizationUri", String.class);
String clientId = config.getValue("client.clientId", String.class);
String redirectUri = config.getValue("client.redirectUri", String.class);
String scope = config.getValue("client.scope", String.class);
```

We'll then append these pieces of information as query parameters to the authorization server's authorization endpoint:

然后我们将把这些信息作为查询参数附加到授权服务器的授权端点。

```java
String authorizationLocation = authorizationUri + "?response_type=code"
  + "&client_id=" + clientId
  + "&redirect_uri=" + redirectUri
  + "&scope=" + scope
  + "&state=" + state;
```

And finally, we'll redirect the browser to this URL:

最后，我们会将浏览器重定向到这个网址。

```java
response.sendRedirect(authorizationLocation);
```

After processing the request, **the authorization server's authorization endpoint will generate and append a code**, in addition to the received state parameter, to the *redirect_uri* and will redirect back the browser [*http://localhost:9081/callback?code=A123&state=Y*](http://localhost:9081/callback?code=A123&state=Y).

处理完请求后，**授权服务器的授权端点除了接收到的状态参数外，还会生成一个代码**，附加到*redirect_uri*中，并将浏览器[*http://localhost:9081/callback?code=A123&state=Y*](http://localhost:9081/callback?code=A123&state=Y)重定向回来。

### 4.3. Access Token Request



The client callback servlet, */callback,* begins by validating the received *state:*

客户端回调servlet，*/callback，*先验证接收到的*状态：*。

```java
String localState = (String) request.getSession().getAttribute("CLIENT_LOCAL_STATE");
if (!localState.equals(request.getParameter("state"))) {
    request.setAttribute("error", "The state attribute doesn't match!");
    dispatch("/", request, response);
    return;
}
```

Next, **we'll use the code we previously received to request an access token** through the authorization server's token endpoint:

接下来，**我们将使用之前收到的代码，通过授权服务器的令牌端点请求访问令牌**。

```java
String code = request.getParameter("code");
Client client = ClientBuilder.newClient();
WebTarget target = client.target(config.getValue("provider.tokenUri", String.class));

Form form = new Form();
form.param("grant_type", "authorization_code");
form.param("code", code);
form.param("redirect_uri", config.getValue("client.redirectUri", String.class));

TokenResponse tokenResponse = target.request(MediaType.APPLICATION_JSON_TYPE)
  .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeaderValue())
  .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE), TokenResponse.class);
```

As we can see, there's no browser interaction for this call, and the  request is made directly using the JAX-RS client API as an HTTP POST.

As the token endpoint requires the client authentication, we have included the client credentials *client_id* and *client_secret* in the *Authorization* header.

The client can use this access token to invoke the resource server APIs which is the subject of the next subsection.

我们可以看到，这个调用没有浏览器交互，直接使用JAX-RS客户端API以HTTP POST的方式进行请求。

由于令牌端点需要客户端认证，我们在*Authorization*头中包含了客户端凭证*client_id*和*client_secret*。

客户端可以使用这个访问令牌来调用资源服务器API，这是下一小节的主题。



### 4.4. Protected Resource Access



**At this point, we have a valid access token and we can call the resource server's /\*read\* and /\*write\* APIs.**

To do that, **we have to provide the \*Authorization\* header**. Using the JAX-RS Client API, this is simply done through the *Invocation.Builder header()* method:

**此时，我们有了一个有效的访问令牌，我们可以调用资源服务器的/\*read\*和/\*write\*API。**

要做到这一点，**我们必须提供\*授权\*头**。使用JAX-RS客户端API，这只需通过*Invocation.Builder header()*方法来完成。

```java
resourceWebTarget = webTarget.path("resource/read");
Invocation.Builder invocationBuilder = resourceWebTarget.request();
response = invocationBuilder
  .header("authorization", tokenResponse.getString("access_token"))
  .get(String.class);
```



## 5. OAuth 2.0 Resource Server



In this section, we'll be building a secured web application based on JAX-RS, MicroProfile JWT, and MicroProfile Config. **The MicroProfile JWT takes care of validating the received JWT and mapping the JWT scopes to Jakarta EE roles**.

在本节中，我们将基于JAX-RS、MicroProfile JWT和MicroProfile Config构建一个安全的Web应用程序。**MicroProfile JWT负责验证收到的JWT，并将JWT作用域映射到Jakarta EE角色**。



### 5.1. Maven Dependencies



In addition to the [Java EE Web API](https://search.maven.org/search?q=g:javax AND a:javaee-web-api&core=gav) dependency, we need also the[ MicroProfile Config](https://search.maven.org/search?q=g:org.eclipse.microprofile.config AND a:microprofile-config-api&core=gav) and [MicroProfile JWT](https://search.maven.org/search?q=g:org.eclipse.microprofile.jwt AND a:microprofile-jwt-auth-api&core=gav) APIs:

除了[Java EE Web API](https://search.maven.org/search?q=g:javax AND a:javaee-web-api&core=gav)依赖，我们还需要[ MicroProfile Config](https://search.maven.org/search?q=g:org.eclipse.microprofile.config AND a:microprofile-config-api&core=gav)和[MicroProfile JWT](https://search.maven.org/search?q=g:org.eclipse.microprofile.jwt AND a:microprofile-jwt-auth-api&core=gav)API。

```xml
<dependency>
    <groupId>javax</groupId>
    <artifactId>javaee-web-api</artifactId>
    <version>8.0</version>
    <scope>provided</scope>
</dependency>
<dependency>
    <groupId>org.eclipse.microprofile.config</groupId>
    <artifactId>microprofile-config-api</artifactId>
    <version>1.3</version>
</dependency>
<dependency>
    <groupId>org.eclipse.microprofile.jwt</groupId>
    <artifactId>microprofile-jwt-auth-api</artifactId>
    <version>1.1</version>
</dependency>
```

### 5.2. JWT Authentication Mechanism



The MicroProfile JWT provides an implementation of the Bearer Token  Authentication mechanism. This takes care of processing the JWT present  in the *Authorization* header, makes available a Jakarta EE Security Principal as a *JsonWebToken* which holds the JWT claims, and maps the scopes to Jakarta EE roles. Take a look at the [Jakarta EE Security API](https://www.baeldung.com/java-ee-8-security) for more background.

To enable the **JWT authentication mechanism in the server,** we need to **add the \*LoginConfig\* annotation** in the JAX-RS application:

MicroProfile JWT提供了一个承载令牌认证机制的实现。它负责处理存在于*Authorization*头中的JWT，使Jakarta EE Security Principal作为一个*JsonWebToken*来持有JWT声明，并将范围映射到Jakarta EE角色。查看[Jakarta EE Security API](https://www.baeldung.com/java-ee-8-security)以了解更多背景。

为了在服务器中启用**JWT认证机制，**我们需要在JAX-RS应用中**添加/*LoginConfig/*注解**。

```java
@ApplicationPath("/api")
@DeclareRoles({"resource.read", "resource.write"})
@LoginConfig(authMethod = "MP-JWT")
public class OAuth2ResourceServerApplication extends Application {
}
```

Additionally, **MicroProfile JWT needs the RSA public key in order to verify the JWT signature**. We can provide this either by introspection or, for simplicity, by  manually copying the key from the authorization server. In either case,  we need to provide the location of the public key:

此外，**MicroProfile JWT需要RSA公钥来验证JWT签名**。我们可以通过自省来提供，或者为了简单起见，从授权服务器上手动复制密钥。在这两种情况下，我们都需要提供公钥的位置。

```plaintext
mp.jwt.verify.publickey.location=/META-INF/public-key.pem
```

Finally, the MicroProfile JWT needs to verify the *iss* claim of the incoming JWT, which should be present and match the value of the MicroProfile Config property:

最后，MicroProfile JWT需要验证传入JWT的*iss*要求，该要求应该是存在的，并且与MicroProfile Config属性的值相匹配。

```plaintext
mp.jwt.verify.issuer=http://127.0.0.1:9080
```

Typically, this is the location of the Authorization Server.

通常情况下，这是授权服务器的位置。



### 5.3. The Secured Endpoints



For demonstration purposes, we'll add a resource API with two endpoints. One is a *read* endpoint that's accessible by users having the *resource.read* scope and another *write* endpoint for users with *resource.write* scope.

The restriction on the scopes is done through the *@RolesAllowed* annotation:

为了演示的目的，我们将添加一个具有两个端点的资源API。一个是*读*端点，拥有*resource.read*作用域的用户可以访问，另一个是*写*端点，供拥有*resource.write*作用域的用户访问。

对作用域的限制是通过*@RolesAllowed*注解完成的。

```java
@Path("/resource")
@RequestScoped
public class ProtectedResource {

    @Inject
    private JsonWebToken principal;

    @GET
    @RolesAllowed("resource.read")
    @Path("/read")
    public String read() {
        return "Protected Resource accessed by : " + principal.getName();
    }

    @POST
    @RolesAllowed("resource.write")
    @Path("/write")
    public String write() {
        return "Protected Resource accessed by : " + principal.getName();
    }
}
```



## 6. Running All Servers



To run one server, we just need to invoke the Maven command in the corresponding directory:

要运行一台服务器，我们只需要在相应的目录下调用Maven命令即可。

```bash
mvn package liberty:run-server
```

The authorization server, the client and the resource server will be  running and available respectively at the following locations:

授权服务器、客户端和资源服务器将分别在以下地点运行和可用。

```plaintext
# Authorization Server
http://localhost:9080/

# Client
http://localhost:9180/

# Resource Server
http://localhost:9280/
```

So, we can access the client home page and then we click on “Get  Access Token” to start the authorization flow. After receiving the  access token, we can access the resource server's *read* and *write* APIs.

Depending on the granted scopes, the resource server will respond  either by a successful message or we'll get an HTTP 403 forbidden  status.

所以，我们可以访问客户端首页，然后我们点击 "获取访问令牌"，启动授权流程。获得访问令牌后，我们就可以访问资源服务器的*读*和*写*API。

根据授予的作用域，资源服务器会以成功的消息来回应，或者我们会得到HTTP 403 forbidden状态。



## 7. Conclusion



In this article, we've provided an implementation of an OAuth 2.0  Authorization Server that can be used with any compatible OAuth 2.0  Client and Resource Server.

To explain the overall framework, we have also provided an  implementation for the client and the resource server. To implement all  these components, we've used using Jakarta EE 8 APIs, especially, CDI,  Servlet, JAX RS, Jakarta EE Security. Additionally, we have used the  pseudo-Jakarta EE APIs of the MicroProfile: MicroProfile Config and  MicroProfile JWT.

The full source code for the examples is available [over on GitHub](https://github.com/eugenp/tutorials/tree/master/oauth2-framework-impl). Note that the code includes an example of both the authorization code and refresh token grant types.

Finally, it's important to be aware of the educational nature of this article and that the example given shouldn't be used in production  systems.



在本文中，我们提供了一个OAuth 2.0授权服务器的实现，它可以与任何兼容的OAuth 2.0客户端和资源服务器一起使用。

为了解释整体框架，我们还提供了客户端和资源服务器的实现。为了实现所有这些组件，我们使用了Jakarta EE 8 API，特别是CDI、Servlet、JAX RS、Jakarta EE Security。此外，我们还使用了MicroProfile的伪Jakarta EE API。MicroProfile Config和MicroProfile JWT。

这些例子的完整源代码可以[在GitHub上](https://github.com/eugenp/tutorials/tree/master/oauth2-framework-impl)。请注意，该代码包括授权代码和刷新令牌授予类型的例子。

最后，需要注意的是，本文的教育性质，所给出的例子不应该用于生产系统中。


