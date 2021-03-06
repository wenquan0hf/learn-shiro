# RememberMe  

Shiro 提供了记住我（RememberMe）的功能，比如访问如淘宝等一些网站时，关闭了浏览器下次再打开时还是能记住你是谁，下次访问时无需再登录即可访问，基本流程如下：

1. 首先在登录页面选中 RememberMe 然后登录成功；如果是浏览器登录，一般会把 RememberMe 的 Cookie 写到客户端并保存下来；
2. 关闭浏览器再重新打开；会发现浏览器还是记住你的；
3. 访问一般的网页服务器端还是知道你是谁，且能正常访问；
4. 但是比如我们访问淘宝时，如果要查看我的订单或进行支付时，此时还是需要再进行身份认证的，以确保当前用户还是你。  

## RememberMe 配置
 
**spring-shiro-web.xml 配置**：

```
<bean id="sessionIdCookie" class="org.apache.shiro.web.servlet.SimpleCookie">
    <constructor-arg value="sid"/>
    <property name="httpOnly" value="true"/>
    <property name="maxAge" value="-1"/>
</bean>
<bean id="rememberMeCookie" class="org.apache.shiro.web.servlet.SimpleCookie">
    <constructor-arg value="rememberMe"/>
    <property name="httpOnly" value="true"/>
    <property name="maxAge" value="2592000"/><!-- 30天 -->
</bean>&nbsp;
```

- sessionIdCookie：maxAge=-1 表示浏览器关闭时失效此 Cookie；  
- rememberMeCookie：即记住我的 Cookie，保存时长 30 天；  

```
`<!-- rememberMe管理器 -->`
<bean id="rememberMeManager" 
class="org.apache.shiro.web.mgt.CookieRememberMeManager">
    <property name="cipherKey" value="
\#{T(org.apache.shiro.codec.Base64).decode('4AvVhmFLUs0KTA3Kprsdag==')}"/>
     <property name="cookie" ref="rememberMeCookie"/>
</bean>&nbsp;
```

rememberMe 管理器，cipherKey 是加密 rememberMe Cookie 的密钥；默认 AES 算法；  

```
`<!-- 安全管理器 -->`
<bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
	……
  <property name="rememberMeManager" ref="rememberMeManager"/>
</bean>&nbsp;
```

设置 securityManager 安全管理器的 rememberMeManager；

```
<bean id="formAuthenticationFilter" 
class="org.apache.shiro.web.filter.authc.FormAuthenticationFilter">
	……
    <property name="rememberMeParam" value="rememberMe"/>
</bean>&nbsp;
```

rememberMeParam，即 rememberMe 请求参数名，请求参数是 boolean 类型，true 表示 rememberMe。  

```
<bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
	……
    <property name="filterChainDefinitions">
        <value>
            /login.jsp = authc
            /logout = logout
            /authenticated.jsp = authc
            /** = user
        </value>
    </property>
</bean>&nbsp;
```

“/authenticated.jsp = authc” 表示访问该地址用户必须身份验证通过（Subject. isAuthenticated()==true）；而 “/** = user” 表示访问该地址的用户是身份验证通过或 RememberMe 登录的都可以。  

**测试**：  

1. 访问 `http://localhost:8080/chapter13/`，会跳转到登录页面，登录成功后会设置会话及 rememberMe Cookie；
2. 关闭浏览器，此时会话 cookie 将失效；
3. 然后重新打开浏览器访问 `http://localhost:8080/chapter13/`，还是可以访问的；
4. 如果此时访问 `http://localhost:8080/chapter13/authenticated.jsp`，会跳转到登录页面重新进行身份验证。  

如果要自己做 RememeberMe，需要在登录之前这样创建 Token：UsernamePasswordToken(用户名，密码，是否记住我)，如：  

```
Subject subject = SecurityUtils.getSubject();
UsernamePasswordToken token = new UsernamePasswordToken(username, password);
token.setRememberMe(true);
subject.login(token);&nbsp;
```

subject.isAuthenticated() 表示用户进行了身份验证登录的，即使有 Subject.login 进行了登录；
subject.isRemembered()：表示用户是通过记住我登录的，此时可能并不是真正的你（如你的朋友使用你的电脑，或者你的 cookie 被窃取）在访问的；且两者二选一，即 subject.isAuthenticated()==true，则 subject.isRemembered()==false；反之一样。

另外对于过滤器，一般这样使用：  
**访问一般网页**，如个人在主页之类的，我们使用 user 拦截器即可，user 拦截器只要用户登录 (isRemembered()==true or isAuthenticated()==true) 过即可访问成功；  
**访问特殊网页**，如我的订单，提交订单页面，我们使用 authc 拦截器即可，authc 拦截器会判断用户是否是通过 Subject.login（isAuthenticated()==true）登录的，如果是才放行，否则会跳转到登录页面叫你重新登录。  
 
因此 RememberMe 使用过程中，需要配合相应的拦截器来实现相应的功能，用错了拦截器可能就不能满足你的需求了。  
 




