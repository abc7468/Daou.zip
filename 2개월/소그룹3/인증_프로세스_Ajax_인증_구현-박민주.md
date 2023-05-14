# # 01. 흐름 및 개요

![image](https://github.com/abc7468/Daou.zip/assets/60870438/7163a66c-08be-4ff0-9376-f02cabff466c)

---

# # 02. 인증 필터 - AjaxAuthenticationFilter

- AbstractAuthenticationProcessingFilter 상속
    - 인증 처리의 기능을 해당 추상 클래스가 지원하고 있다.
- 필터 작동 조건
    - AntPathRequestMatcher(”/ajaxLogin”)로 요청정보와 매칭하고 요청 방식이 Ajax 이면 필터가 작동한다.
- `AjaxAuthenticationToken`을 생성해 `AuthenticationManager`에게 전달하여 인증을 처리한다.
    - username과 password를 전달하는 token
- Filter 추가
    - `http.addFilterBefore(AjaxAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)`
    - 인증 처리 시 UsernamePassword(Form 인증 방식 필터) 앞에 Ajax필터가 실행된다.

## AjaxAuthenticationFilter

```java
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    //    ajaxLogin 해당 url로 왔을 때 인증처리를 진행한다.
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/ajaxLogin", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {

// Ajax 요청이 아니라면
        if (!isAjax(request)){
            throw new IllegalStateException("Authentication is not supported");
        }

// AccounDto가 아니라면 or 인증하려는 객체가 비어있다면
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalArgumentException("Username or Password is empty");
        }

// AuthenticationManager에게 전달
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    private boolean isAjax(HttpServletRequest request) {
        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))){
            return true;
        }
        return false;
    }

}
```

## AjaxAuthenticationToken

```java
public class AjaxAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    // 인증 전 생성되는 토큰
    public AjaxAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    // 인증 후 생성되는 토큰
    public AjaxAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
```

- Ajax에 사용되는 토큰 생성

## AjaxSecurityConfig

```java

@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
								.antMatcher("/api/**") // 해당 URL로 들어온 
                .authorizeRequests()
                .anyRequest().authenticated() // 어떤 요청에도 자원 접근이 허용된 사용자만 가능하다
                .and()
                .addFilterBefore(ajaxLoginProcessingFilter2(), UsernamePasswordAuthenticationFilter.class);
        http
                .csrf().disable();
    }

    @Bean
    public AjaxLoginProcessingFilter2 ajaxLoginProcessingFilter2() throws Exception {
        AjaxLoginProcessingFilter2 ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter2();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager());
        return ajaxLoginProcessingFilter;
    }

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
```

### 필터 위치 정하기

```java
.addFilterBefore() // 현재 추가하고 싶은 필터가 기존 필터 앞에서 동작하길 원할 경우
.addFilter() // 가장 마지막에 위치할 때
.addFilterAfter() // 현재 추가하고자 하는 필터가 기존 필터 뒤에 위치할 때
.addFilterAt() // 기존 필터의 위치를 대체하고자 할 때
```

---

# #03. 인증 처리자 - AjaxAuthenticationProvider

## AjaxAuthenticationProvider

```java
@Slf4j
public class AjaxAuthenticationProvider2 implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    private PasswordEncoder passwordEncoder;

    public AjaxAuthenticationProvider2(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 검증을 위한
        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        // 추가 검증을 위해 UserDetails를 반환한다.
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(loginId);

        if (!passwordEncoder.matches(password, accountContext.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

// 최종 인증 정보와 권한 정보를 담아 반환한다.
        return new AjaxAuthenticationToken2(accountContext.getAccount(), null, accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 토큰의 타입 검증
        return authentication.equals(AjaxAuthenticationToken2.class);
    }
}
```

- 앞서 만든 ajaxToken을 사용해 생성한다.
- manager에게 인증객체를 위임받아 provider가 실행된다.
- 인증 객체(Authentication)에는 로그인한 아이디와 비밀번호가 들어있다.
- 해당 정보를 사용해 인증 객체를 반환받는다.

### AccountContext

```java
@Data
public class AccountContext extends User {
  private Account account;

  public AccountContext(Account account, List<GrantedAuthority> roles) {
    super(account.getUsername(), account.getPassword(), roles);
    this.account = account;
  }
}
```

- 이제 앞서 정한 것들을 config에 추가한다.

## AjaxSecurityConfig

```java
@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

/// 추가
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider2());
    }

    @Bean
    public AjaxAuthenticationProvider2 ajaxAuthenticationProvider2() {
        return new AjaxAuthenticationProvider2();
    }
/// 추가 

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(ajaxLoginProcessingFilter2(), UsernamePasswordAuthenticationFilter.class);
        http
                .csrf().disable();
    }

    @Bean
    public AjaxLoginProcessingFilter2 ajaxLoginProcessingFilter2() throws Exception {
        AjaxLoginProcessingFilter2 ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter2();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager());
        return ajaxLoginProcessingFilter;
    }

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
```

- FilterChain을 따라가면 설정한 필터가 동작하는 것을 볼 수 있다.
    
    ![image](https://github.com/abc7468/Daou.zip/assets/60870438/e9135e2f-ea57-4b07-b2fd-5bf85708706f)
    
- Filter → Manager → Provider (반대로 반)
- parent에 ajaxProvider이 존재한다.
    
    ![image](https://github.com/abc7468/Daou.zip/assets/60870438/fc867b53-3e80-427e-b25d-b0419e28180a)
    

---

# #04. 인증 핸들러 - AjaxAuthenticationSuccessHanlder, AjaxAuthenticationFailureHandler

- provider에서 ID/PW 검증한다.
- 그리고 Token을 만들어 Manager에게 전달하고 Manager는 현재 진행하는 Filter에게 다시 전달해 인증 이후의 작업을 처리하도록 한다.
    - 성공시 → SuccessHandler
    - 실패시 → FailureHandler
- 현재는 인증 이후의 값을 Response Body에 담아서 반환하자.

## AjaxSuccessHandler

```java
public class AjaxAuthenticationSuccessHandler2 implements AuthenticationSuccessHandler {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // provider에서 최종적으로 accout 객체를 저장했다.
        Account account = (Account) authentication.getPrincipal();

        // response 응답
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // objectMapper가 json 형식으로 제너럴해 account 객체를 담아준다.
        objectMapper.writeValue(response.getWriter(), account);
    }
}
```

## AjaxFailureHandler

```java
public class AjaxAuthenticationFailureHandler2 implements AuthenticationFailureHandler {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errMsg = "Invalid Username or Password";

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (exception instanceof BadCredentialsException) {
            errMsg = "Invalid Username or Password";
        } else if (exception instanceof DisabledException) {
            errMsg = "Locked";
        } else if (exception instanceof CredentialsExpiredException) {
            errMsg = "Expired password";
        }

        // 인증 실패시 인증 예외 타입에 따라 메시지가 담겨 전달된다.
        objectMapper.writeValue(response.getWriter(), errMsg);
    }
}
```

- 이후 Filter에 Bean으로 등록후, 추가해준다.

## AjaxFilter

```java
@Bean
    public AjaxLoginProcessingFilter2 ajaxLoginProcessingFilter2() throws Exception {
        AjaxLoginProcessingFilter2 filter = new AjaxLoginProcessingFilter2();
        filter.setAuthenticationManager(authenticationManager());
        // filter에 Bean 추가
        filter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler2());
        filter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler2());
        return filter;
    }

@Bean
    public AjaxAuthenticationSuccessHandler2 ajaxAuthenticationSuccessHandler2() {
        return new AjaxAuthenticationSuccessHandler2();
    }

@Bean
    public AjaxAuthenticationFailureHandler2 ajaxAuthenticationFailureHandler2() {
        return new AjaxAuthenticationFailureHandler2();
    }
```

---

# #05. 인증 및 인가 예외 처리 - AjaxLoginUrlAuthenticationEntryPoint, AjaxAccessDeniedHandler

- 인증을 받지 못한 사용자가 인증이 필요 자원에 접근했을 경우, 사용자가 인증을 다시 받을 수 있도록 해줘야 한다.
- 인증을 받은 사용자가 특정 권한이 필요한 자원에 접근했을 경우, 권한이 없을 경우에 대한 처리 또한 해주어야 한다.

- `FilterSecurityInterceptor`: 인가 처리하는 클래스
    - 자격/권한을 판단한다.
    - 인증을 받지 않았다면 인증을 다시 받도록 한다.
    
    ```java
    // AbstractSecurityInterceptor.java 
    // Attempt authorization
    		try {
    			this.accessDecisionManager.decide(authenticated, object, attributes);
    		}
    		catch (AccessDeniedException accessDeniedException) {
    			publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated,
    					accessDeniedException));
    
    			throw accessDeniedException;
    		}
    ```
    
    - 이는 ExveptionTranslationFilter가 받는다.
    
    ```java
    else if (exception instanceof AccessDeniedException) {
    			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    			// 1)
    			if (authenticationTrustResolver.isAnonymous(authentication) || authenticationTrustResolver.isRememberMe(authentication)) {
    				logger.debug(
    						"Access is denied (user is " + (authenticationTrustResolver.isAnonymous(authentication) ? "anonymous" : "not fully authenticated") + "); redirecting to authentication entry point",
    						exception);
    
    				sendStartAuthentication(
    						request,
    						response,
    						chain,
    						new InsufficientAuthenticationException(
    							messages.getMessage(
    								"ExceptionTranslationFilter.insufficientAuthentication",
    								"Full authentication is required to access this resource")));
    			}
    			// 2)
    			else {
    				logger.debug(
    						"Access is denied (user is not anonymous); delegating to AccessDeniedHandler",
    						exception);
    
    				accessDeniedHandler.handle(request, response,
    						(AccessDeniedException) exception);
    			}
    ```
    
    - `AccessDeniedException` 발생
        
        1) anonymous 즉 익명 사용자가 접근한 경우
        
        ```java
        protected void sendStartAuthentication(HttpServletRequest request,
        			HttpServletResponse response, FilterChain chain,
        			AuthenticationException reason) throws ServletException, IOException {
        		SecurityContextHolder.getContext().setAuthentication(null);
        		requestCache.saveRequest(request, response);
        		logger.debug("Calling Authentication entry point.");
        		// entryPoint 호출 -> like 로그인 페이지로 이동
        		authenticationEntryPoint.commence(request, response, reason);
        	}
        ```
        
        2) 인증했지만 권한이 없는 경우
        
        - handler를 호출해 처리한다.

1. 인증받지 않은 사용자

## AjaxEntryPoint

```java
public class AjaxLoginAuthenticationEntryPoint2 implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        // 인증받지 못한 사용자가 접근했을 경우
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");
    }
}
```

1. 권한이 없는 사용자

## AjaxAccessDeniedHandler

```java
public class AjaxAccessDeniedHandler2 implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 필요한 권한이 없는 사용자가 접근했을 경우
				response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access is denied");
    }
}
```

- config에 추가

## AjaxConfig

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")..;
        http
                .exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint2())
                .accessDeniedHandler(ajaxAccessDeniedHandler2());
        http
                .csrf().disable();

    }
```

---

# #06. Ajax Custom DSLs 구현하기

> DSL로 Config 설정하기
> 

- Custom DSLs
    - AbstractHttpConfigurer
        - 스프링 시큐리티 초기화 설정 클래스
        - 필터, 핸들러, 메서드, 속성 등을 한 곳에 정의하여 처리할 수 있는 편리함을 제공한다.
        - public void init(H http) throws Exception - 초기화
        - public void configure(H http) - 설정
    - HttpSecurity의 apply(C configurer) 메서드 사용
- DSL?
    - 도메인 특화 언어(Domain-specific language)
    - 특정한 도메인을 적용하는데 특화된 언어

### 레퍼런스

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/5956d33b-4a95-4129-8b92-6b10e4ab1f6c/Untitled.png)

- 적용
    
    ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/4ea52ce0-93af-4905-bc4d-92c89cf2e5d2/Untitled.png)
    
- 연결
    
    ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d2e443ff-7ffb-4e18-b2cd-928c92d68450/Untitled.png)
    

## AjaxLoginConfigurer

```java
// configure()
getAuthenticationFilter().setAuthenticationManager(authenticationManager);
getAuthenticationFilter().setAuthenticationSuccessHandler(successHandler);
getAuthenticationFilter().setAuthenticationFailureHandler(failureHandler);
// loginConfigurer의 이 부분은 우리가 Filter에서 적용했던 하단과 동일하다.

@Bean
    public AjaxLoginProcessingFilter2 ajaxLoginProcessingFilter2() throws Exception {
        AjaxLoginProcessingFilter2 filter = new AjaxLoginProcessingFilter2();
        filter.setAuthenticationManager(authenticationManager());
        // filter에 Bean 추가
        filter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler2());
        filter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler2());
        return filter;
    }

http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
// 필터를 연결하는 부분은

// config의 체이닝과 같음
.addFilterBefore(ajaxLoginProcessingFilter2(), UsernamePasswordAuthenticationFilter.class);
```

- 전체

```java
public final class AjaxLoginConfigurer2<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurer2<H>, AjaxLoginProcessingFilter2> {

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private AuthenticationManager authenticationManager;

    //  생성자에선 필터를 만들어 부모 클래스에게 전달한다.
    public AjaxLoginConfigurer2() {
        super(new AjaxLoginProcessingFilter2(), null);
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(H http) { // H는 HttpSecurity 객체

        if(authenticationManager == null){
            // getSharedObject 공유 객체를 저장하고 가져올 수 있는 저장소
            authenticationManager = http.getSharedObject(AuthenticationManager.class);
        }
        // getAuthenticationFilter: 생성자에서 넘겨준 필터를 가져오게 된다.
        getAuthenticationFilter().setAuthenticationManager(authenticationManager);
        getAuthenticationFilter().setAuthenticationSuccessHandler(successHandler);
        getAuthenticationFilter().setAuthenticationFailureHandler(failureHandler);

        // 인증 받을 때 설정
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http
                .getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            getAuthenticationFilter().setRememberMeServices(rememberMeServices);
        }

        // 필터를 다시 저장?
        http.setSharedObject(AjaxLoginProcessingFilter2.class,getAuthenticationFilter());

        http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    public AjaxLoginConfigurer2<H> successHandlerAjax(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    public AjaxLoginConfigurer2<H> failureHandlerAjax(AuthenticationFailureHandler authenticationFailureHandler) {
        this.failureHandler = authenticationFailureHandler;
        return this;
    }

    public AjaxLoginConfigurer2<H> setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }

    // login Process Url을 파라미터로 전달하기
    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

}
```

## AjaxSecurityConfig

```java
@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider2());
    }

    @Bean
    public AjaxAuthenticationProvider2 ajaxAuthenticationProvider2() {
        return new AjaxAuthenticationProvider2();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .anyRequest().authenticated();
// 주석처리: dsl에서 설정하고 있음
//                .and()
//                .addFilterBefore(ajaxLoginProcessingFilter2(), UsernamePasswordAuthenticationFilter.class);
        http
                .exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint2())
                .accessDeniedHandler(ajaxAccessDeniedHandler2());
        http
                .csrf().disable();

        customConfigurerAjax(http);

    }

// DSL 설정
    private void customConfigurerAjax(HttpSecurity http) throws Exception {
        http
                .apply(new AjaxLoginConfigurer2<>())
                .successHandlerAjax(ajaxAuthenticationSuccessHandler2())
                .failureHandlerAjax(ajaxAuthenticationFailureHandler2())
                .setAuthenticationManager(authenticationManager())
								// from의 action tag
                .loginProcessingUrl("/api/login");
    }

// 주석처리: dsl에서 설정하고 있음
//    @Bean
//    public AjaxLoginProcessingFilter2 ajaxLoginProcessingFilter2() throws Exception {
//        AjaxLoginProcessingFilter2 filter = new AjaxLoginProcessingFilter2();
//        filter.setAuthenticationManager(authenticationManager());
//        // filter에 Bean 추가
//        filter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler2());
//        filter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler2());
//        return filter;
//    }
}
```

- AbstractConfigurerSecurityBuilder에서는 여러 config가 체이닝 되어 있고 configure 혹은 init 메서드를 실행한다.
    
    ![맨 마지막에 추가된 AjaxLoginConfigurer](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/448d949b-9c12-4622-96b8-305a8cd1fdcc/Untitled.png)
    
    맨 마지막에 추가된 AjaxLoginConfigurer
    
    ![그리고 안에 설정한 여러 클래스가 연결되어 있다.](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c91200b5-3b05-4141-b570-d9e1d5c9d2b8/Untitled.png)
    
    그리고 안에 설정한 여러 클래스가 연결되어 있다.
    

---

# #07. Ajax 로그인 구현 & CSRF 설

- 헤더 설정
    - 전송 방식이 Ajax인지의 여부를 위한 헤더설정
        - xhr.setRequestHeader(”X-Requested-With”, “XMLHttpRequest”);
    - CSRF 헤더 설정
        - <meta id=”_csrf” name=”_csrf” th:content=””${_csrf.token}” />
            - _csrf.token: 서버에서 발급한 토큰
        - <meta id=”_csrf_header” name=”_csrf_header” th:content=””${_csrf.headerName}” />
        - var csrfHeader = $(’meta[name=”_csrf_header”]’).attr(’content’)
        - var csrfToken = $(’meta[name=”_csrf”]’).attr(’content’)
        - xhr.setRequestHeader(csrfHeader, csrfToken);
    - ajax 방식으로 진행할 때는 csrf를 직접 생성해야한다.
    - thyeamleaf를 사용하면 form tag 사용 시 csrf token을 자동으로 만들어준다.

```jsx
// login.html
<html xmlns:th="http://www.thymeleaf.org">

// 페이지 로딩 시 설정된 값
<meta id="_csrf" name="_csrf" th:content="${_csrf.token}"/>
<meta id="_csrf_header" name="_csrf_header" th:content="${_csrf.headerName}"/>

<head th:replace="layout/header::userHead"></head>
<script>
    function formLogin(e) {

        var username = $("input[name='username']").val().trim();
        var password = $("input[name='password']").val().trim();
        var data = {"username" : username, "password" : password};

        var csrfHeader = $('meta[name="_csrf_header"]').attr('content')
        var csrfToken = $('meta[name="_csrf"]').attr('content')

        $.ajax({
            type: "post",
            url: "/api/login",
            data: JSON.stringify(data),
            dataType: "json",
            beforeSend : function(xhr){
                // xhr.setRequestHeader(csrfHeader, csrfToken);
                xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
                xhr.setRequestHeader("Content-type","application/json");
            },
            success: function (data) {
                console.log(data);
                window.location = '/';

            },
            error : function(xhr, status, error) {
                console.log(error);
                window.location = '/login?error=true&exception=' + xhr.responseText;
            }
        });
    }
</script>
```
