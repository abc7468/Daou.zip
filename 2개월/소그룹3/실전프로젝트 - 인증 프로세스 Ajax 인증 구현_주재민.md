# 실전프로젝트 - 인증 프로세스 Ajax 인증 구현

## 흐름 및 개요

---

**흐름 개요**

<img width="1003" alt="Untitled" src="https://user-images.githubusercontent.com/57485510/232930647-e24f1e53-ca1b-4179-955f-b944962daa0c.png">

> 위 코드는 직접 만든다
> 

인증처리는 모두 필터로 시작해서 필터로 끝난다. 

- 인증 처리를 위임하는 순서가 가장 위 `AjaxAuthenticationFilter` ↔ `AjaxAuthenticationProvider` 흐름이다
- 그러고 나면,인증의 성공/실패를 처리하는 `AjaxAuthentication{Success/Failure}Handler`가 진행한다
- 인증에 성공하면, 인가를 처리하는 `FilterSecurityInterceptor`가 처리를 시작하나
- 인가에 대한 예외가 발생하게 되면, `ExceptionTranslationFilter`가 처리하게 된다
    - 인증 실패 예외 : `AjaxUrlAuthenticationEntryPoint` ← `AjaxAuthentication{Success/Failure}Handler`는 예외처리가 아니라, 인증에 실패했을 때, 어떤 동작이 수행되어야 하는 것들을 정의하는 것이다
    - 자원 접근 예외 : `AjaxAccessDeniedHandler`

## 인증 필터 - AjaxAuthenticationFilter

---

### AjaxAuthenticationFilter

`AbstractAuthenticationProcessingFilter`를 상속

- 이 클래스는 Form인증처리를 맡은 `UsernamePasswordAuthenticationFilter`도 이 클래스를 상속받음
- 필터 작동 조건: `new AntPathRequestMatcher("/api/login")` 으로 들어오는 것과 **Ajax 요청 방식**ㅇ이면 필터 작동
- 인증 처리 로직: `AjaxAuthenticationToken` 생성 → `AuthenticationManager`에게 전달

Filter 추가방법

```java
http.addFilterBefore(AjaxAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
```

- AjaxAuthenticationFilter가 `UsernamePasswordAuthenticationFilter` 전에 먼저 동작하도록 설정

### AjaxAuthenticationFilter 실제 구현

- AjaxAuthentcationFilter(`AjaxLoginProcessingFilterCopy`)생성
    
    ```java
    public class AjaxLoginProcessingFilterCopy extends AbstractAuthenticationProcessingFilter {
    
        private final ObjectMapper mapper = new ObjectMapper();
    
        public AjaxLoginProcessingFilterCopy() {
            super(new AntPathRequestMatcher("/api/login")); 1)
        }
    
        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
            if(!isAjax(request)){
                throw new IllegalStateException("Authentication is not supported");
            }
    
            AccountDto accountDto = mapper.readValue(request.getReader(), AccountDto.class);
            if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
                throw new IllegalArgumentException("username or password is empty");
            }
    
            AjaxAuthenticationTokenCopy tokenCopy = new AjaxAuthenticationTokenCopy(accountDto.getUsername(), accountDto.getPassword()); 2)
    
            return getAuthenticationManager().authenticate(tokenCopy); 3)
        }
        private static boolean isAjax(HttpServletRequest request) {
            return "XMLHttpRequest".equals(request.getHeader("X-Request-With"));
        }
    }
    ```
    
    - 1) “/api/login”으로 들어온 요청을 처리하겠다
    - 2) 해당 요청으로 들어온 ID/PWD로 `Authentication`객체를 만들겠다
    - 3) 해당 filter가 가지고 있는 `AuthenticationManager`에게 만든 `Authentication`객체를 넘긴다
- `AjaxAuthentcationToken` 생성
    
    ```java
    public class AjaxAuthenticationTokenCopy extends AbstractAuthenticationToken {
        //...
    
        public AjaxAuthenticationTokenCopy(Object principal, Object credentials) {
            // 인증 받기 전에, 사용자가 입력하는 로그인 아이디, 패스워드를 담는 생성자
            super((Collection)null);
            this.principal = principal;
            this.credentials = credentials;
            this.setAuthenticated(false);
        }
    
        public AjaxAuthenticationTokenCopy(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
            // 인증 이후에, 인증에 성공한 결과를 담는 생성자
            super(authorities);
            this.principal = principal;
            this.credentials = credentials;
            super.setAuthenticated(true);
        }
    
      //...
    }
    ```
    
    - 위 주석을 읽어보자
- `SpringSecurityConfig` 설정에 AjaxAuthenticationFilter(`AjaxLoginProcessingFilterCopy`)를 설정
    
    ```java
    public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                .and()
                    .addFilterBefore(ajaxLoginProcessingFilterCopy(), UsernamePasswordAuthenticationFilter.class) 1)
                    .authorizeRequests()
                    //...
    
            http.csrf().disable(); // POST 통신에서는 CSRF토큰을 가지고 통신을 해야 시큐리티에서 검사하기 때문에 토큰이 필요하다. 테스트용으로 잠시 disable
        }
    
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception { 2)
            return super.authenticationManagerBean();
        }
    
        @Bean
        public AjaxLoginProcessingFilterCopy ajaxLoginProcessingFilterCopy() 3) throws Exception {
            AjaxLoginProcessingFilterCopy ajaxLoginProcessingFilterCopy = new AjaxLoginProcessingFilterCopy();
            ajaxLoginProcessingFilterCopy.setAuthenticationManager(authenticationManagerBean()); 4)
            return ajaxLoginProcessingFilterCopy;
        }
    }
    ```
    
    - 1) `UsernamePasswordAuthenticationFilter`보다 전에 검사해줘라
    - 2), 4) `authentctionManagerBean`은 아직 `AjaxLoginProcessingFilterCopy`전용 manager가 없으니, 대체용
    - 3) `ajaxLoginProcessingFilterCopy`() 객체를 만들어서 1) `HttpSecurity`에 적용

## 인증 처리자 - AjaxAuthenticationProvider

---

### AjaxAuthentication을 위한 Config 파일을 분리해보자

- 코드
    
    ```java
    @Configuration
    @Slf4j
    @Order(0) 1)
    public class AjaxSecurityConfigCopy extends WebSecurityConfigurerAdapter{
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/api/**")
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .addFilterBefore(ajaxLoginProcessingFilterCopy(), UsernamePasswordAuthenticationFilter.class);
    
            http.csrf().disable(); // POST 통신에서는 CSRF토큰을 가지고 통신을 해야 시큐리티에서 검사하기 때문에 토큰이 필요하다. 테스트용으로 잠시 disable
        }
    
        @Bean
        public AjaxLoginProcessingFilterCopy ajaxLoginProcessingFilterCopy() throws Exception {
            AjaxLoginProcessingFilterCopy ajaxLoginProcessingFilterCopy = new AjaxLoginProcessingFilterCopy();
            ajaxLoginProcessingFilterCopy.setAuthenticationManager(authenticationManagerBean());
            return ajaxLoginProcessingFilterCopy;
        }
    }
    ```
    
    - `Order(0)`으로 제일 먼저 Security설정을 읽어들이도록 설정 ← SpringSecurityConfig는 `Order(1)`

### AjaxAuthenticationProvider를 만들어보자

Provider는 사실, Form인증 때와 크게 달라진 것이 없다. 그 이유는, 

만약, 만들지 않는다면 위 AjaxAuthenticationFilter(`AjaxLoginProcessingFilterCopy`)는 인증처리를 하지 않는다

- 왜? filter로 걸렀는데 “인증 로직”은 없으니까
- 코드
    
    ```java
    public class AjaxAuthenticationProviderCopy implements AuthenticationProvider {
        // ...
    
        @Override
        @Transactional
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    
            //...
    
            return new AjaxAuthenticationTokenCopy 1)(accountContext.getAccount(), null, accountContext.getAuthorities());
        }
    
        @Override
        public boolean supports(Class<?> authentication) {
            return authentication.equals(AjaxAuthenticationToken.class); 2)
        }
    }
    ```
    
    - 1) 인증에 성공한 객체가 `AjaxAuthenticationTokenCopy`로 되도록 변경
    - 2) authentication 비교에 `AjaxAuthenticationTokenCopy`객체를 비교하도록 변경

## 인증 핸들러 - AjaxAuthenticationSuccessHandler, AjaxAuthenticationFailureHandler

---

### Form인증과 다른점

REST방식으로 요청이 들어온 것 

- 즉, 페이지로 redirect하는 방식이 아니라, 특정 응답 값을 만들어서 보내줘야 한다
- Response Body를 만들어서 보내주자

### AjaxAuthenticationSuccess/FailureHandler를 만들어보자

`AjaxAuthenticationSuccessHandler`

```java
public class AjaxAuthenticationSuccessHandlerCopy implements AuthenticationSuccessHandler {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Account account = (Account) authentication.getPrincipal();

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        mapper.writeValue(response.getWriter(), account);
    }
}
```

- REST API응답으로 전달하기 위해 ResponseBody에 담는 코드이다

`AjaxAuthenticationFailureHandler`

```java
public class AjaxAuthenticationFailureHandlerCopy implements AuthenticationFailureHandler {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = "Invalid username or password";

        // ...

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        mapper.writeValue(response.getWriter(), errorMessage);
    }
}
```

- REST API응답으로 전달하기 위해 ResponseBody에 담는 코드이다
- `//…` ← 이 부분은 Form인증 핸들러처럼, 예외를 처리하는 동일 로직이다

`AjaxSecurityConfig`

```java
@Configuration
@Slf4j
@Order(0)
public class AjaxSecurityConfigCopy extends WebSecurityConfigurerAdapter{
		//...

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return new AjaxAuthenticationSuccessHandlerCopy();
    } 1)

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(){
        return new AjaxAuthenticationFailureHandlerCopy();
    } 2)

		// ...

    @Bean
    public AjaxLoginProcessingFilterCopy ajaxLoginProcessingFilterCopy() throws Exception {
        AjaxLoginProcessingFilterCopy ajaxLoginProcessingFilterCopy = new AjaxLoginProcessingFilterCopy();
        ajaxLoginProcessingFilterCopy.setAuthenticationManager(authenticationManagerBean());
        ajaxLoginProcessingFilterCopy.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        ajaxLoginProcessingFilterCopy.setAuthenticationFailureHandler(authenticationFailureHandler()); 3)
        
        return ajaxLoginProcessingFilterCopy;
    }
}
```

- 1), 2) SuccessHandler, FailureHandler를 빈으로 등록해주고
- 3) 이를 AjaxAuthenticationFilter(`AjaxLoginProcessingFilterCopy`)에 등록해준다

## 인증 및 인가 예외 처리 - AjaxLoginurlAuthenticationEntryPoint, AjaxAccessDeniedHandler

---

### 예외 처리 내용

**AjaxLoginAuthenticationEntryPoint**

- **인증을 받지 못한 사용자**가 어떤 자원에 접근했는데, 그 자원이 인증이 필요하다면 다시 로그인을 통해 인증을 받을 수 있도록 하는 역할
- AuthenticationEntryPoint를 상속

**AjaxAccessDeniedHandler**

- **인증을 받은 사용자**가 자원에 접근했는데, 해당 자원이 특정한 권한을 가져야만 접근이 가능한데 사용자는 그 권한이 없을 때 처리하는 역할
- AccessDeniedHandler를 상속

흐름부터 파악

1. FilterSecurityInterceptor
    - 자원에 접근하기 위해서는 인증을 다시 받아야하는지 여부 파악
    - AccessDeniedException 던지면, ExceptionTranslationFilter가 받음
2. ExceptionTranslationFilter
    - 인증을 받지 않은 사용자가 자원 접근할 때 ⇒ AuthenticationEntryPoint에 던짐
    - 인증은 받았지만 권한이 없을 때 ⇒ AccessDeniedHandler에 던진다

### 2가지 클래스 만들어보자

AjaxLoginAuthenticationEntryPoint

```java
public class AjaxLoginAuthenticationEntryPointCopy implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");
    }
}
```

AjaxAccessDeniedHandler

```java
public class AjaxAccessDeniedHandlerCopy implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access is Denied");

    }
}
```

AjaxSecurityConfig 설정

```java
@Configuration
@Slf4j
@Order(0)
public class AjaxSecurityConfigCopy extends WebSecurityConfigurerAdapter{

    //...
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/api/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .antMatchers("/api/messages").hasRole("MANAGER") 1)
                .and()
                .addFilterBefore(ajaxLoginProcessingFilterCopy(), UsernamePasswordAuthenticationFilter.class);

        http.exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPointCopy()) 2)
                .accessDeniedHandler(ajaxAccessDeniedHandler()); 3)

        http.csrf().disable(); // POST 통신에서는 CSRF토큰을 가지고 통신을 해야 시큐리티에서 검사하기 때문에 토큰이 필요하다. 테스트용으로 잠시 disable
    }
		
		@Bean
    public AccessDeniedHandler ajaxAccessDeniedHandler(){
        return new AjaxAccessDeniedHandlerCopy();
    }

   //...
}
```

- 1) “/api/messages”에 접근하려면 MANAGER 권한이 있어야한다
- 2) 위 URL로 들어오는 접근의 **인증 예외**는  AjaxLoginAuthenticationEntryPointCopy로 처리해라
- 3) 위 URL로 들어오는 접근의 **인가 예외**는  AjaxAccessDeniedHandlerCopy로 처리해라

접근하고자 하는 API

```java
@Controller
public class MessageController {
 	 //...
   @GetMapping("/api/messages")
   public String apiMessage(){
      return "message ok";
   }
} 
```

## Ajax Custom DSLs 구현하기

---

DSL? 도메인 특화 언어는  특정한 도메인을 적용하는데 특화된 언어…? 의미는 이러하

### Custom DSLs

AbstractHttpConfigurer

- 스프링 시큐리티 초기화 설정 클래스
- 필터, 핸들러, 메서드, 속성 → 한 곳에 정의하고 처리하도록 만드는 편리함
- 메서드
    - `public void init(HttpSecurity http)`
    - `public void configure(HttpSecurity http)`

위에 클래스만 만들고, 적용은 어떻게?

- HttpSecurity의 apply메서드 이용
- SecurityConfig파일과 비슷한 것일까? 생각이 든다?
    - 아니였다 → 설정을 만들어서 http.apply형태로 SecurityConfig에 붙여주는것, 즉 예를 들면 Ajax설정을 분리해서 만들고 붙여주는 개념

Custom DSL(AjaxLoginConfigurerCopy)를 만들어보자

- AjaxLoginConfigurerCopy 코드
    
    ```java
    public class AjaxLoginConfigurerCopy<H extends HttpSecurityBuilder<H>> extends AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurerCopy<H>, AjaxLoginProcessingFilterCopy> {
        private AuthenticationSuccessHandler successHandler;
        private AuthenticationFailureHandler failureHandler;
        private AuthenticationManager authenticationManager;
    
        public AjaxLoginConfigurerCopy() {
            super(new AjaxLoginProcessingFilterCopy(), null);
        }
    
        @Override
        public void init(H http) throws Exception {
            super.init(http);
        }
    
        @Override
        public void configure(H http) throws Exception {
            if(authenticationManager == null){
                authenticationManager = http.getSharedObject(AuthenticationManager.class);
            }
            getAuthenticationFilter().setAuthenticationManager(authenticationManager);
            getAuthenticationFilter().setAuthenticationSuccessHandler(successHandler);
            getAuthenticationFilter().setAuthenticationFailureHandler(failureHandler);
    
            SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);
            if(sessionAuthenticationStrategy != null){
                getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
            }
    
            RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
            if(rememberMeServices != null){
                getAuthenticationFilter().setRememberMeServices(rememberMeServices);
            }
    
            http.setSharedObject(AjaxLoginProcessingFilterCopy.class, getAuthenticationFilter());
            http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        }
    
        public AjaxLoginConfigurerCopy<H> loginPage(String loginPage) {
            return super.loginPage(loginPage);
        }
    
        public AjaxLoginConfigurerCopy<H> successHandlerAjax(AuthenticationSuccessHandler successHandler) {
            this.successHandler = successHandler;
            return this;
        }
    
        public AjaxLoginConfigurerCopy<H> failureHandlerAjax(AuthenticationFailureHandler failureHandler) {
            this.failureHandler = failureHandler;
            return this;
        }
    
        public AjaxLoginConfigurerCopy<H> setAuthenticationManager(AuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
            return this;
        }
    
        @Override
        protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
            return new AntPathRequestMatcher(loginProcessingUrl, "POST");
        }
    }
    ```
    
- AjaxSecurityConfig 코드
    
    ```java
    @Configuration
    @Order(0)
    public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {
    		//...
    
        private void ajaxConfigurer(HttpSecurity http) throws Exception {
            http
                    .apply(new AjaxLoginConfigurerCopy<>())
                    .successHandlerAjax(ajaxAuthenticationSuccessHandler())
                    .failureHandlerAjax(ajaxAuthenticationFailureHandler())
                    .loginPage("/api/login")
                    .loginProcessingUrl("/api/login")
                    .setAuthenticationManager(authenticationManagerBean());
        }
    
    }
    ```
    

위 2가지 코드를 같이 설명하자면 이런 것이다

- DSL이 무엇이라고? 도메인 특화된 언어를 제공한 것
- 기본적으로 HttpSecurity가 제공하는 메서드가 아니라, 내가 Ajax 관련 Security 설정에 대한 핸들링을 하고 있다는 것을 명확하게 확인할 수 있다
- 실제로, 내부적으로 어떻게 프로퍼티들을 적용하는지가 분리되어 있다보니, [필터, 핸들러, 메서드, 속성]에 대한 자세한 내용없이도 메서드를 “도메인특화”되게 사용가능하다
- 즉, 기본제공만으로도 설정할 수 있지만 ↔ 더욱 명확한 역할을 같도록 Ajax 보안을 맡은 SecurityConfig를 생성하여 초기화할 수 있다

실제로 HttpSecurityBuilder에서 AjaxLoginConfigurer라는 설정 객체를 만든다!

- 설정 객체 리스트
    
    <img width="628" alt="Untitled 1" src="https://user-images.githubusercontent.com/57485510/232930638-4e15310c-c2cb-40a9-b267-81bc7924928f.png">
    

## Ajax 로그인 구현 & CSRF 설정

---

### 로그인 Ajax 구현

헤더부터 확인

- 전송 방식이 Ajax인지 여부를 위한 헤더 설정
    - xhr.setRequestHeader(”X-Requested-With”, “XMLHttpRequest”);

CSRF 헤더 설정

- 설정 코드가 있다.
    - Thymeleaf가 Form인증에 CSRF 설정을 해준다
    - Ajax로 통신할 때는 CSRF 헤더를 설정해주어야 한다.
        
        ```html
        <!-- hody -->
        <meta id="_csrf" name="_csrf" th:content="${_csrf.token}"/>
        <meta id="_csrf_header" name="_csrf_header" th:content="${_csrf.headerName}"/>
        
        <!-- script -->
        var csrfHeader = $('meta[name="_csrf_header"]').attr('content')
        var csrfToken = $('meta[name="_csrf"]').attr('content')
        xhr.setRequestHeader(csrfHeader, csrfToken);
        ```