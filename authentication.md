# 身份验证

**身份验证**，即在应用中谁能证明他就是他本人。一般提供如他们的身份 ID 一些标识信息来表明他就是他本人，如提供身份证，用户名 / 密码来证明。

在 shiro 中，用户需要提供 principals （身份）和 credentials（证明）给 shiro，从而应用能验证用户身份：

**principals**：身份，即主体的标识属性，可以是任何东西，如用户名、邮箱等，唯一即可。一个主体可以有多个 principals，但只有一个 Primary principals，一般是用户名 / 密码 / 手机号。

**credentials**：证明 / 凭证，即只有主体知道的安全值，如密码 / 数字证书等。

最常见的 principals 和 credentials 组合就是用户名 / 密码了。接下来先进行一个基本的身份认证。

另外两个相关的概念是之前提到的 **Subject** 及 **Realm**，分别是主体及验证主体的数据源。

## 环境准备

本文使用 Maven 构建，因此需要一点 Maven 知识。首先准备环境依赖：

```
<dependencies>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.9</version>
    </dependency>
    <dependency>
        <groupId>commons-logging</groupId>
        <artifactId>commons-logging</artifactId>
        <version>1.1.3</version>
    </dependency>
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-core</artifactId>
        <version>1.2.2</version>
    </dependency>
</dependencies>
```

添加 junit、common-logging 及 shiro-core 依赖即可。

## 登录 / 退出

1、首先准备一些用户身份 / 凭据（shiro.ini）

```
[users]
zhang=123
wang=123
```

此处使用 ini 配置文件，通过 [users] 指定了两个主体：zhang/123、wang/123。

2、测试用例（com.github.zhangkaitao.shiro.chapter2.LoginLogoutTest） 

```
@Test
public void testHelloworld() {
    //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager  Factory<org.apache.shiro.mgt.SecurityManager> factory =
            new IniSecurityManagerFactory("classpath:shiro.ini");
    //2、得到SecurityManager实例 并绑定给SecurityUtils   org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
    SecurityUtils.setSecurityManager(securityManager);
    //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
    Subject subject = SecurityUtils.getSubject();
    UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
    try {
        //4、登录，即身份验证
        subject.login(token);
    } catch (AuthenticationException e) {
        //5、身份验证失败
    }
    Assert.assertEquals(true, subject.isAuthenticated()); //断言用户已经登录
    //6、退出
    subject.logout();
}
```

- 首先通过 new IniSecurityManagerFactory 并指定一个 ini 配置文件来创建一个 SecurityManager 工厂；

- 接着获取 SecurityManager 并绑定到 SecurityUtils，这是一个全局设置，设置一次即可；

- 通过 SecurityUtils 得到 Subject，其会自动绑定到当前线程；如果在 web 环境在请求结束时需要解除绑定；然后获取身份验证的 Token，如用户名 / 密码；

- 调用 subject.login 方法进行登录，其会自动委托给 SecurityManager.login 方法进行登录；

- 如果身份验证失败请捕获 AuthenticationException 或其子类，常见的如： DisabledAccountException（禁用的帐号）、LockedAccountException（锁定的帐号）、UnknownAccountException（错误的帐号）、ExcessiveAttemptsException（登录失败次数过多）、IncorrectCredentialsException （错误的凭证）、ExpiredCredentialsException（过期的凭证）等，具体请查看其继承关系；对于页面的错误消息展示，最好使用如 “用户名 / 密码错误” 而不是 “用户名错误”/“密码错误”，防止一些恶意用户非法扫描帐号库；

- 最后可以调用 subject.logout 退出，其会自动委托给 SecurityManager.logout 方法退出。

**从如上代码可总结出身份验证的步骤**：

1. 收集用户身份 / 凭证，即如用户名 / 密码；

2. 调用 Subject.login 进行登录，如果失败将得到相应的 AuthenticationException 异常，根据异常提示用户错误信息；否则登录成功；

3. 最后调用 Subject.logout 进行退出操作。

如上测试的几个问题：

1. 用户名 / 密码硬编码在 ini 配置文件，以后需要改成如数据库存储，且密码需要加密存储；

2. 用户身份 Token 可能不仅仅是用户名 / 密码，也可能还有其他的，如登录时允许用户名 / 邮箱 / 手机号同时登录。 

## 身份认证流程

![](images/4.png)

流程如下：

1. 首先调用 Subject.login(token) 进行登录，其会自动委托给 Security Manager，调用之前必须通过 SecurityUtils.setSecurityManager() 设置；
2. SecurityManager 负责真正的身份验证逻辑；它会委托给 Authenticator 进行身份验证；
3. Authenticator 才是真正的身份验证者，Shiro API 中核心的身份认证入口点，此处可以自定义插入自己的实现；
4. Authenticator 可能会委托给相应的 AuthenticationStrategy 进行多 Realm 身份验证，默认 ModularRealmAuthenticator 会调用 AuthenticationStrategy 进行多 Realm 身份验证；
5. Authenticator 会把相应的 token 传入 Realm，从 Realm 获取身份验证信息，如果没有返回 / 抛出异常表示身份验证失败了。此处可以配置多个 Realm，将按照相应的顺序及策略进行访问。

## Realm

Realm：域，Shiro 从从 Realm 获取安全数据（如用户、角色、权限），就是说 SecurityManager 要验证用户身份，那么它需要从 Realm 获取相应的用户进行比较以确定用户身份是否合法；也需要从 Realm 得到用户相应的角色 / 权限进行验证用户是否能进行操作；可以把 Realm 看成 DataSource，即安全数据源。如我们之前的 ini 配置方式将使用 org.apache.shiro.realm.text.IniRealm。

org.apache.shiro.realm.Realm 接口如下：

```
String getName(); //返回一个唯一的Realm名字
boolean supports(AuthenticationToken token); //判断此Realm是否支持此Token
AuthenticationInfo getAuthenticationInfo(AuthenticationToken token)
 throws AuthenticationException;  //根据Token获取认证信息
```

**单 Realm 配置**

1、自定义 Realm 实现（com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1）：

```
public class MyRealm1 implements Realm {
    @Override
    public String getName() {
        return "myrealm1";
    }
    @Override
    public boolean supports(AuthenticationToken token) {
        //仅支持UsernamePasswordToken类型的Token
        return token instanceof UsernamePasswordToken; 
    }
    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String)token.getPrincipal();  //得到用户名
        String password = new String((char[])token.getCredentials()); //得到密码
        if(!"zhang".equals(username)) {
            throw new UnknownAccountException(); //如果用户名错误
        }
        if(!"123".equals(password)) {
            throw new IncorrectCredentialsException(); //如果密码错误
        }
        //如果身份认证验证成功，返回一个AuthenticationInfo实现；
        return new SimpleAuthenticationInfo(username, password, getName());
    }
}&nbsp;
```

2、ini 配置文件指定自定义 Realm 实现 (shiro-realm.ini)  

```
\#声明一个realm
myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1
\#指定securityManager的realms实现
securityManager.realms=$myRealm1&nbsp;
```

通过 $name 来引入之前的 realm 定义

3、测试用例请参考 com.github.zhangkaitao.shiro.chapter2.LoginLogoutTest 的 testCustomRealm 测试方法，只需要把之前的 shiro.ini 配置文件改成 shiro-realm.ini 即可。

**多 Realm 配置**

1、ini 配置文件（shiro-multi-realm.ini）

```
\#声明一个realm
myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1
myRealm2=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm2
\#指定securityManager的realms实现
securityManager.realms=$myRealm1,$myRealm2&nbsp;
```

securityManager 会按照 realms 指定的顺序进行身份认证。此处我们使用显示指定顺序的方式指定了 Realm 的顺序，如果删除 “securityManager.realms=$myRealm1,$myRealm2”，那么securityManager 会按照 realm 声明的顺序进行使用（即无需设置 realms 属性，其会自动发现），当我们显示指定 realm 后，其他没有指定 realm 将被忽略，如 “securityManager.realms=$myRealm1”，那么 myRealm2 不会被自动设置进去。

2、测试用例请参考 com.github.zhangkaitao.shiro.chapter2.LoginLogoutTest 的 testCustomMultiRealm 测试方法。

**Shiro 默认提供的 Realm**

![](images/5.png)

以后一般继承 AuthorizingRealm（授权）即可；其继承了 AuthenticatingRealm（即身份验证），而且也间接继承了 CachingRealm（带有缓存实现）。其中主要默认实现如下：

**org.apache.shiro.realm.text.IniRealm**：[users] 部分指定用户名 / 密码及其角色；[roles] 部分指定角色即权限信息；

**org.apache.shiro.realm.text.PropertiesRealm**： user.username=password,role1,role2 指定用户名 / 密码及其角色；role.role1=permission1,permission2 指定角色及权限信息；

**org.apache.shiro.realm.jdbc.JdbcRealm**：通过 sql 查询相应的信息，如 “select password from users where username = ?” 获取用户密码，“select password, password_salt from users where username = ?” 获取用户密码及盐；“select role_name from user_roles where username = ?” 获取用户角色；“select permission from roles_permissions where role_name = ?” 获取角色对应的权限信息；也可以调用相应的 api 进行自定义 sql；

**JDBC Realm 使用**

1、数据库及依赖

```
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>5.1.25</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid</artifactId>
            <version>0.2.23</version>
        </dependency>&nbsp;
```

本文将使用 mysql 数据库及 druid 连接池； 

2、到数据库 shiro 下建三张表：users（用户名 / 密码）、user\_roles（用户 / 角色）、roles\_permissions（角色 / 权限），具体请参照 shiro-example-chapter2/sql/shiro.sql；并添加一个用户记录，用户名 / 密码为 zhang/123；
 
3、ini 配置（shiro-jdbc-realm.ini）

```
jdbcRealm=org.apache.shiro.realm.jdbc.JdbcRealm
dataSource=com.alibaba.druid.pool.DruidDataSource
dataSource.driverClassName=com.mysql.jdbc.Driver
dataSource.url=jdbc:mysql://localhost:3306/shiro
dataSource.username=root
\#dataSource.password=
jdbcRealm.dataSource=$dataSource
securityManager.realms=$jdbcRealm&nbsp;
```

1. 变量名 = 全限定类名会自动创建一个类实例
2. 变量名. 属性 = 值 自动调用相应的 setter 方法进行赋值
3. $ 变量名 引用之前的一个对象实例 
4. 测试代码请参照 com.github.zhangkaitao.shiro.chapter2.LoginLogoutTest 的 testJDBCRealm 方法，和之前的没什么区别。

## Authenticator 及 AuthenticationStrategy

Authenticator 的职责是验证用户帐号，是 Shiro API 中身份验证核心的入口点：

```
public AuthenticationInfo authenticate(AuthenticationToken authenticationToken)
            throws AuthenticationException;&nbsp;
```

如果验证成功，将返回 AuthenticationInfo 验证信息；此信息中包含了身份及凭证；如果验证失败将抛出相应的 AuthenticationException 实现。

SecurityManager 接口继承了 Authenticator，另外还有一个 ModularRealmAuthenticator 实现，其委托给多个 Realm 进行验证，验证规则通过 AuthenticationStrategy 接口指定，默认提供的实现：

**FirstSuccessfulStrategy**：只要有一个 Realm 验证成功即可，只返回第一个 Realm 身份验证成功的认证信息，其他的忽略；

**AtLeastOneSuccessfulStrategy**：只要有一个 Realm 验证成功即可，和 FirstSuccessfulStrategy 不同，返回所有 Realm 身份验证成功的认证信息；

**AllSuccessfulStrategy**：所有 Realm 验证成功才算成功，且返回所有 Realm 身份验证成功的认证信息，如果有一个失败就失败了。

ModularRealmAuthenticator 默认使用 AtLeastOneSuccessfulStrategy 策略。

假设我们有三个 realm：  
myRealm1： 用户名 / 密码为 zhang/123 时成功，且返回身份 / 凭据为 zhang/123；  
myRealm2： 用户名 / 密码为 wang/123 时成功，且返回身份 / 凭据为 wang/123；  
myRealm3： 用户名 / 密码为 zhang/123 时成功，且返回身份 / 凭据为 zhang@163.com/123，和 myRealm1 不同的是返回时的身份变了；  

1、ini 配置文件 (shiro-authenticator-all-success.ini)   

```
\#指定securityManager的authenticator实现
authenticator=org.apache.shiro.authc.pam.ModularRealmAuthenticator
securityManager.authenticator=$authenticator
\#指定securityManager.authenticator的authenticationStrategy
allSuccessfulStrategy=org.apache.shiro.authc.pam.AllSuccessfulStrategy
securityManager.authenticator.authenticationStrategy=$allSuccessfulStrategy
```

```
myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1
myRealm2=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm2
myRealm3=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm3
securityManager.realms=$myRealm1,$myRealm3
```

2、测试代码（com.github.zhangkaitao.shiro.chapter2.AuthenticatorTest）

- 首先通用化登录逻辑

```
    private void login(String configFile) {
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory(configFile);
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        subject.login(token);
    }
```

- 测试 AllSuccessfulStrategy 成功：

```
    @Test
    public void testAllSuccessfulStrategyWithSuccess() {
        login("classpath:shiro-authenticator-all-success.ini");
        Subject subject = SecurityUtils.getSubject();
        //得到一个身份集合，其包含了Realm验证成功的身份信息
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(2, principalCollection.asList().size());
    }&nbsp;
```

即 PrincipalCollection 包含了 zhang 和 zhang@163.com 身份信息。

- 测试 AllSuccessfulStrategy 失败：

```
    @Test(expected = UnknownAccountException.class)
    public void testAllSuccessfulStrategyWithFail() {
        login("classpath:shiro-authenticator-all-fail.ini");
        Subject subject = SecurityUtils.getSubject();
}&nbsp;
```

shiro-authenticator-all-fail.ini 与 shiro-authenticator-all-success.ini 不同的配置是使用了 securityManager.realms=$myRealm1，$myRealm2；即 myRealm 验证失败。

对于 AtLeastOneSuccessfulStrategy 和 FirstSuccessfulStrategy 的区别，请参照 testAtLeastOneSuccessfulStrategyWithSuccess 和 testFirstOneSuccessfulStrategyWithSuccess 测试方法。唯一不同点一个是返回所有验证成功的 Realm 的认证信息；另一个是只返回第一个验证成功的 Realm 的认证信息。

自定义 AuthenticationStrategy 实现，首先看其 API：

```
//在所有Realm验证之前调用
AuthenticationInfo beforeAllAttempts(
Collection<? extends Realm> realms, AuthenticationToken token) 
throws AuthenticationException;
//在每个Realm之前调用
AuthenticationInfo beforeAttempt(
Realm realm, AuthenticationToken token, AuthenticationInfo aggregate) 
throws AuthenticationException;
//在每个Realm之后调用
AuthenticationInfo afterAttempt(
Realm realm, AuthenticationToken token, 
AuthenticationInfo singleRealmInfo, AuthenticationInfo aggregateInfo, Throwable t)
throws AuthenticationException;
//在所有Realm之后调用
AuthenticationInfo afterAllAttempts(
AuthenticationToken token, AuthenticationInfo aggregate) 
throws AuthenticationException;&nbsp;
```

因为每个 AuthenticationStrategy 实例都是无状态的，所有每次都通过接口将相应的认证信息传入下一次流程；通过如上接口可以进行如合并 / 返回第一个验证成功的认证信息。

自定义实现时一般继承 org.apache.shiro.authc.pam.AbstractAuthenticationStrategy 即可，具体可以参考代码 com.github.zhangkaitao.shiro.chapter2.authenticator.strategy 包下 OnlyOneAuthenticatorStrategy 和 AtLeastTwoAuthenticatorStrategy。

到此基本的身份验证就搞定了，对于 AuthenticationToken 、AuthenticationInfo 和 Realm 的详细使用后续章节再陆续介绍。










