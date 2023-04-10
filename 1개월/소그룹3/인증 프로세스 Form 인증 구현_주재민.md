# 실전프로젝트 - 인증 프로세스 Form 인증 구현

## 실전프로젝트 - 무엇을 만들 것인가?

---

우리가 만들 것은 무엇일까?

- 대시보드 메뉴
- 마이페이지 메뉴
- 메시지 메뉴
- 환경설정 메뉴

각 메뉴마다 다른 권한으로 접근할 수 있도록 만들 것이다 

## 정적 자원 관리 - WebIgnore 설정

---

개념

- js / css / img 파일 등등 보안필터를 적용할 필요가 없는 리소스 설정

```java
@override
public void configure(WebSecurity web) throws Exception{
		web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
}
```

### PasswordEncoder

`PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()`

- 여러개의 PassowrdEncoder 유형이 있는데, 이를 선택해서 사용할 수 있도록 지원
- 기본 포멧 → Bcrypt
    - 이 외에도, SHA-1, scrypt
- 인터페이스
    - `encode(password)` : 암호화
    - `matches(rawPwd, encodedPwd)` : 패스워드 비교

## DB 연동 인증 처리

---

### CustomUserDetailService

DB에서 사용자를 조회해서 인증처리를 이루어지도록 만들어보자

- `AccountContext`: `CustomUserDetailService`가 반환할 때 `UserDetails`로 해야되는데 그 구현체
- `UserDetailsService`를 구현해서, `username`을 통해 `Account`를 구한다
- `Account` 객체와 권한 정보를 만들어서 → `AccountContextCopy`(User를 커스텀한) 를 생성한다
- `AccountContextCopy`를 리턴(아래 코드)
    
    ```java
    public class AccountContextCopy extends User {
    
       // ...
    }
    ```
    
- 

이렇게 만든 UserDetailsService 클래스를 Security에 등록해줘야 한다

```java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception { 
      auth.userDetailsService(userDetailsService);
}
```

- 이렇게 설정하면, 스프링 시큐리티가 등록한 `userDetailsSerivce`로 인증을 처리한다
    
    ```java
    @RequiredArgsConstructor
    //@Service("userDetailsService")
    public class CustomUserDetailsService implements UserDetailsService {
        private final UserRepository userRepository;
    
        @Override
        public UserDetails loadUserByUsername(Stringusername) throws UsernameNotFoundException {
            ...
        }
    }
    ```
    
- SecurityConfig에 설정
    
    ```java
    private final UserDetailsService userDetailsService;
    
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailsService);
    		}
    }
    ```
    

### CustomAuthenticationProvider

Security에 UserDetailsService 클래스까지 적용했다면, Provider객체가 실제 인증을 처리할 수 있도록 판을 깔아주자

- `AccountContext` 클래스로 사용자 보안 `User`객체를 만들고, 이를 `UserDetailsService`에서 불러오면
- `Provider`가 `AccountContext`정보로 인증을 처리할 수 있도록 하자
- 이 정보들로, `UsernamePasswordAuthenticationToken`객체를 만들어 `AuthenticationManager`가 리턴받을 수 있도록 만든다
    
    ```java
    @RequiredArgsConstructor
    public class CustomAuthenticationProvider implements AuthenticationProvider {
    
        private final UserDetailsService userDetailsService;
        private final PasswordEncoder passwordEncoder;
    
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            // 검증을 위한 로직
        }
    
        @Override
        public boolean supports(Class<?> authentication) {
            // 파라미터로 전달되는 Authentication 타입과 해당 Provider가 사용하고자 하는 토큰의 타입과 일치하는지 확인
            return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        }
    }
    ```
    
- 결국, 이 결과도 `SecurityConfig`에 설정해주자
    
    ```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }
    
    private AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
    }
    ```
    

## 커스텀 로그인 페이지 생성하기

---

### 간단하게 설정

로그인 페이지는 2가지 설정만 하면 된다.

- `SecurityConfig` 설정
    
    ```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //...
                .formLogin()
                .loginPage("/login/copy")
                .loginProcessingUrl("/copy")
                .defaultSuccessUrl("/copy")
                .permitAll();
    
    }
    ```
    
- `Controller` 설정
    
    ```java
    @GetMapping("/login/copy")
    public String login(){
        return "user/login/login";
    }
    ```
    

## 로그아웃 및 인증에 따른 화면 보안 처리

---

### 로그아웃 처리 핸들러

GET요청으로 들어오면 SecurityContextLogoutHandler 활용

- `Thymeleaf Security` 처리
    
    ```html
    <li class="nav-item" sec:authorize="isAnonymous()"><a class="nav-link text-light" th:href="@{/login}">로그인</a></li>
    <li class="nav-item" sec:authorize="isAnonymous()"><a class="nav-link text-light" th:href="@{/users}">회원가입</a></li>
    ```
    
- `Controller`에 logout 핸들러 적용
    
    ```java
    @GetMapping("/logout/copy")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    
        if(authentication != null){
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "redirect:/login";
    }
    ```
    

## 인증 부가 기능 - WebAuthenticationDetails, AuthenticationDetailsSource

---

<img width="1021" alt="Untitled" src="https://user-images.githubusercontent.com/57485510/229701921-a76487c5-90ec-4a31-a5a5-2871f523b46f.png">

### WebAuthenticationDetails

인증 과정 중에 파라미터가 넘어왔을 때, 전달된 데이터를 저장

- `Authentication`객체의 details 속성에 저장된다
    - `Object`타입으로 타입과 관계없이 저장이 가능
    - `details`에 `WebAuthenticationDetails`객체가 담긴다

### AuthenticationDetailsSource

- `WebAuthenticationDetails`의 생성 역할을 맡음
- `WebAuthenticationDetails`에서는 기본적으로 `remoteAddress`, `sessionId`를 저장
    - 추가적으로 파라미터가 오면, 이는  `request.getParameter`를 통해 저장한다

### Custom으로 파라미터를 details에 저장하는 로직을 추가해보자

- `FormWebAuthenticationDetailsCopy` 코드
    
    ```java
    public class FormWebAuthenticationDetailsCopy extends WebAuthenticationDetails {
        private String secretKey;
    
        public FormWebAuthenticationDetailsCopy(HttpServletRequest request) {
            super(request);
            secretKey = request.getParameter("secret_key");
        }
    // ...
    }
    ```
    
- `FromWebAuthenticationDetailsSourceCopy` 코드
    
    ```java
    public class FromWebAuthenticationDetailsSourceCopy implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    
        @Override
        public WebAuthenticationDetails buildDetails(HttpServletRequest request) {
            return new FormWebAuthenticationDetailsCopy(request);
        }
    }
    ```
    
- `SpringSecurityConfig` 코드
    
    ```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
    						//...
                .loginPage("/login/copy")
                .loginProcessingUrl("/copy")
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/copy")
                .permitAll();
    
    }
    ```
    

`FormWebAuthenticationDetailsCopy`를 보면 “secretKey”를 `request`객체에서 꺼낸다

- 이를 활용해서 `secretKey`를 받아와야만 인증처리하도록 만들어보자
    
    ```java
    @RequiredArgsConstructor
    public class CustomAuthenticationProvider implements AuthenticationProvider {
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            // 검증을 위한 로직
    
            //...
            FormWebAuthenticationDetailsCopy formWebAuthenticationDetails = (FormWebAuthenticationDetailsCopy) authentication.getDetails();
            String secretKey = formWebAuthenticationDetails.getSecretKey();
            if (secretKey == null || "secret".equals(secretKey)) {
                throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
            }
    
            return new UsernamePasswordAuthenticationToken(accountContextCopy, null, accountContextCopy.getAuthorities());
        }
    
       //...
    }
    ```
    

## 인증성공 핸들러: CustomAuthenticationSuccessHandler

---

### CustomAuthenticationSuccessHandler

SpringSecurity에서 제공하는 기본 AuthenticationSuccessHandler를 상속받아서 설정해보자

- 상황을 하나 만들어보자
    - requestCache를 통해, 사용자가 인증에 실패하고, 다시 인증에 시도해 성공하면 가려고 했던 페이지로 이동하도록 설정해보자
- **`SuccessHandler`** 코드 ← `SimpleUrlAuthenticationSuccessHandler`를 상속받음
    
    ```java
    @Component
    public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
        private final RequestCache requestCache = new HttpSessionRequestCache();
        private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    
        @Override
        public void onAuthenticationSuccess(HttpServletRequestrequest, HttpServletResponseresponse, FilterChainchain, Authenticationauthentication) throws IOException, ServletException {
            SavedRequest savedRequest= requestCache.getRequest(request,response);
            if(savedRequest!= null){
                StringtargetUrl=savedRequest.getRedirectUrl();
                redirectStrategy.sendRedirect(request,response,targetUrl);
            }else{
                redirectStrategy.sendRedirect(request,response, getDefaultTargetUrl());
            }
    
        }
    }
    ```
    
    - 로그인을 하지 않은 상태 → “`/mypage`”로 접근
        - 이미 예외를 통해서 “`/login`”페이지가 redirect로 왔다
        - 하지만, 여기서 로그인하면 바로 “`/mypage`”로 접근이 가능하도록 설정해놨다
            
            → `SavedRequest savedRequest= requestCache.getRequest(request,response);`
            → `savedRequest.getRedirectUrl()`
            

Config에 Custom한 SuccessHandler를 적용해보자

- `SecurityConfig`
    
    ```java
    @RequiredArgsConstructor
    public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    
    		private final AuthenticationSuccessHandler authenticationSuccessHandler;
    		
    		@Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    //...
                    .successHandler(authenticationSuccessHandler)
                    .permitAll();
        }
    }
    ```
    
    - `SimpleAuthenticationSuccessHandler`를 상속받았기 때문에 ComponentScan으로 `CustomAuthenticationSuccessHandler`를 찾아온다.

## 인증실패 핸들러: CustomeAuthenticationFailureHandler

---

### CustomeAuthenticationFailureHandler

인증에 실패했을 경우, 동일하게 인증 필터가 실패했을 때 후속작업을 커스텀하게 만들어보자

- 인증에 실패한 경우, error 여부와 exception메시지를 redirectUrl에 담아 전송하도록 만들어보자
- `CustomAuthenticationFailureHandler`
    
    ```java
    @Component
    public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
            // 예외 메시지를 클라이언트에게 뿌리는 코드 짜보기
            String errorMessage = "Invalid Username or Password";
    
            if (exception instanceof BadCredentialsException) {
                errorMessage = errorMessage;
            } else if (exception instanceof InsufficientAuthenticationException) {
                errorMessage = "Invalid Secret Key";
            }
    
            setDefaultFailureUrl("/login?error=true&exception=" + exception.getMessage());
    
            super.onAuthenticationFailure(request, response, exception);
        }
    
    }
    ```
    
    - `setDefaultFailureUrl`로 redirect url에 담을 parameter를 설정해준다
- `Controller`
    
    ```java
    @GetMapping("/login/copy")
    public String login(@RequestParam(value="error", required = false) String error, @RequestParam(value = "exception", required = false) String exception, Model model){
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
    
        return "login";
    }
    ```
    
    - request parameter로 error여부와 exception message 처리까지 처리하도록 설정
- `SecurityConfig`
    
    ```java
    public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
        private final AuthenticationSuccessHandler authenticationSuccessHandler; // SimpleAuthenticationSuccessHandler를 상속받았기 때문에 ComponentScan으로 Custom...Handler를 찾아온다.
        private final AuthenticationFailureHandler authenticationFailureHandler;
    
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
    								.antMatchers("/copy","user/login/**", "/login*").permitAll()
                    //...
                    .successHandler(authenticationSuccessHandler)
                    .failureHandler(authenticationFailureHandler)
                    .permitAll();
        }
    }
    ```
    
    - `.antMatchers("/copy","user/login/**", "/login")` ← login 뒤에 파라미터 값이 붙어서 와도 처리 가능해지도록 설정

## 인증 거부 처리 - Access Denied

---

### Access Denied

인증은 성공했다! 자원에 접근해야지~~ … 자원에 대한 권한이 없네..ㅠ

인가에 대한 권한을 체크하는 클래스

- `AbstractSecurityInterceptor`
    - 인가에 대한 권한이 없으면 → `AccessDeniedException`을 던진다

`AbstractSecurityInterceptor`에서 던진 예외를 받는 필터

- `ExceptionTranslationFilter`가 받는다

### AccessDeniedHandler를 커스텀화 해보자

- `CustomAccessDeniedHandler` 코드
    
    ```java
    public class CustomAccessDeniedHandler implements AccessDeniedHandler {
        String errorPage;
    
        @Override
        public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException accessDeninedException) throws IOException, ServletException {
            // 현재 사용자가 접근하고 하는 자원에 접근할 수 없음을 Client에게 전달해보자
            String deniedUrl = errorPage + "?exception=" + accessDeninedException.getMessage();
    				response.sendRedirect(deniedUrl);
        }
    
        public void setErrorPage(String errorPage){
            this.errorPage = errorPage;
        }
    }
    ```
    
- `Controller` 코드
    
    ```java
    @GetMapping("/denied")
    public String accessDenied(@RequestParam(value="exception", required = false) String exception, Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = (Account)authentication.getPrincipal();
    
        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);
    
        return "user/login/denied";
    }
    ```
    
- `SecurityConfig` 코드
    
    ```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
            .and()
    						//...
    }
    
    private static AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler();
    }
    ```
    

흐름

- CustomAccessDeniedHandler로 인해 redirect로 예외 내용이 전달
- Controller에 redirect로 들어온 예외 내용을 Model 객체에 담아 Client에 전달
- Client에서 Model에 저장된 내용을 꺼내서 화면에 뿌리기