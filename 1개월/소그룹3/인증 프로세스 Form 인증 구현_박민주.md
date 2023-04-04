# 3. 인증 프로세스 Form 인증 구현

---

# # 01. 실전 프로젝트 생성

- github: https://github.com/onjsdnjs/corespringsecurity
    - branch: ch05-01
- 추후 버전 업그레이드 필수

### SecurityConfig

```java
@Override
		protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // 권한 부여
								.antMatchers("/").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin();
}
```

- `authorizeRequests()`: 인증에 대한 로직 실행
- `antMatchers({요청 url}).hasRole({권한})`: 해당 요청 url에 접속하기 위한(인가에 필요한) 권한
- `anyRequest().authenticated(`): 모든 요청은 인증받아야한다.
- `formLogin()`: form 기반 로그인 사용

```java
@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // inmemory로 사용자 넣기
        String password = passwordEncoder().encode("1111");
        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER");
        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN");
}
```

- 임시 사용자 만들기
    - inmemory 기법 사용
    - 비밀번호는 인코딩해야한다.

```java
@Bean
    public PasswordEncoder passwordEncoder() {
        // 평문인 패스워드 암호화
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
```

---

# # 02. WebIgnore 설정

- 클라이언트가 서버 요청을 하게 되면 시큐리티는 해당 요청을 받아 사용자가 자격/권한이 있는지 확인하는 과정을 거친다.
- 요청한 자원의 정적인 자원 관리
    - 시큐리티는 정적인 자원도(모든 자원에 대) 보안을 검사한다.
- js/css/image 파일 등 보안 필터를 적용할 필요가 없는 리소스를 설정해줄 수 있다.
- 추후에 권한 계층을 설정할 수 있다.

```java
@Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
```

- ignoring과 permitAll의 차이점
    - 공통점은 인증/권한에 관련 자격이 없어도 통과한다.
    - `.antMatchers("/").permitAll()`
        - 보안 필터 안에 들어와 요청을 처리(success/fail)한다.
    - `web.ignoring()`
        - 보안 필터 자체를 거치지 않는다.
- FilterSecurityInterceptor

### 프로젝트 설명

- pom.xml: 의존성 추가

```xml
<dependency> // 두 객체 사이에 매
    <groupId>org.modelmapper</groupId>
    <artifactId>modelmapper</artifactId>
    <version>2.3.0</version>
</dependency>
```

- 설정 추가

```java
// jpa를 위한 설정 추
spring.jpa.hibernate.ddl-auto=create
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.properties.hibernate.format_sql=true
spring.jpa.properties.hibernate.show_sql=true
spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation=true

// 서버를 기동하지 않아도 즉각적으로 화면을 볼 수 있다.
spring.devtools.livereload.enabled=true
spring.devtools.restart.enabled=true
```

---

# # 03. 사용자 DB 등록 및 PasswordEncoder

- 비밀번호를 안전하게 저장할 수 있도록 암호화 기능을 제공한다.
- `DelegatingPasswordEncoder`: 여러 암호화 방식을 가지고 구현하고 있다.
- 암호화 포맷: `{id}encodedPassword`
    - 기본 포멧은 Bcypt: {bcypt}$…
    - 알고리즘 종류: bcypt, sha256, …
- 인터페이스 종류
    - `.encoded(password)`: 패스워드 암호화
    - `.matches(rawPassword, encodedPassword)`: 패스워드 비교

```java
@PostMapping(value="/users")
	public String createUser(AccountDto accountDto) throws Exception {

		ModelMapper modelMapper = new ModelMapper();
// dto와 entity 매
		Account account = modelMapper.map(accountDto, Account.class);
// 비밀번호 암호화
		account.setPassword(passwordEncoder.encode(accountDto.getPassword()));

		userService.createUser(account);

		return "redirect:/";
	}
```

---

# # 04. DB 연동 인증 처리: CustomUserDetailsService

### CustomUserDetailsService

```java
@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account = userRepository.findByUsername(username);
        if (account == null) {
            if (userRepository.countByUsername(username) == 0) {
                throw new UsernameNotFoundException("No user found with username: " + username);
            }
        }

        List<GrantedAuthority> roles = new ArrayList<>();
			// USER 라는 권한 부여
        roles.add(new SimpleGrantedAuthority(account.getRoles()));
        
        return new AccountContext(account, roles);
    }
}
```

데이터 계층에서 account 객체를 가져와 USER라는 권한을 부여하고 있다.

- 직접 DB에 연동이 되도록?

### AccountContext extends User

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

- User 를 상속받은 객체

### SecurityConfig

```java
@Autowired
private UserDetailsService userDetailsService;

@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }
```

- userDetailsService를 사용해 인증처리를 진행한다.
- 인증 시 userDetailsService의 loadUserByUsername 메서드가 실행된다.
- DB에서 값을 꺼내 User 객체를 상속받은 accountContext 를 반환한다.

---

# # 05. DB 연동 인리 - CustomAuthenticationProvider

- UserDetails를 받아 추가 인증 처리를 하는 `Provider`

### CustomAuthenticationProvider

```java
public class FormAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    private PasswordEncoder passwordEncoder;

    public FormAuthenticationProvider(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 검증을 위한 로직
        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        // 추가 검증을 위해 UserDetails를 반환한다.
         AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(loginId);

        if (!passwordEncoder.matches(password, accountContext.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 토큰의 타입 검증
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

### SecurityConfig

```java
@Bean
    public AuthenticationProvider authenticationProvider(){
        return new CustomAuthenticationProvider();
    }

@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }
```

---

# # 06. 커스텀 로그인 페이지 생성하기

### SecurityConfig

```java
@Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // 권한 부여
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .permitAll();
}
```

### LoginController

```java
@GetMapping(value="/login")
	public String login(){
		return "user/login/login";
	}
```

---

# # 07. 로그아웃 및 인증에 따른 화면 보안 처리

- 로그아웃 방법
    
    1) <form> 태그를 이용한 POST 요청: `LogoutFliter` 사용
    
    2) <a> 태그를 이용한 GET 요청: `SecurityContextLogoutHandler` 활용
    
- 인증 여부에 따른 로그인/로그아웃 표현
    - isAnonymous()
    - isAuthenticated()
    
    ```html
    <li class="nav-item" sec:authorize="isAnonymous()"><a class="nav-link text-light" th:href="@{/login}">로그인</a></li>
    <li class="nav-item" sec:authorize="isAnonymous()"><a class="nav-link text-light" th:href="@{/users}">회원가입</a></li>
    <li class="nav-item" sec:authorize="isAuthenticated()"><a class="nav-link text-light" th:href="@{/logout}">로그아웃</a></li>
    ```
    

### LoginController

```java
@GetMapping(value = "/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) throws Exception {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null){
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}

		return "redirect:/login";
	}
```

- Get 방식

---

# # 08. 인증 부가 기능 - WebAuthenticationDetails, AuthenticationDetailsSource

![image](https://user-images.githubusercontent.com/60870438/229543074-27169a59-0ecb-4abd-aa96-1ee5360ae623.png)
  
1. `AuthenticationFilter`
    - 추가적인 데이터를 담아 사용할 수 있다.
        - `WebAuthenticationDetails`이고 이 클래스를 생성하는 것이 `AuthenticationDetailsSource`이다.
2. `Authentication` 생성
    - ID/PW
    - details
3. `AuthenticationDetailsSource`
    - `WebAuthenticationDetails` 생성
4. `WebAuthenticationDetails`
    - 사용자가 추가적으로 담은 데이터를 활용한다.
    - request.getParams
    - remoteAddress
    - SessionId
    - 등 을 담아 details를 반환한다.

### FormWebAuthenticationDetails

- 사용자가 추가적으로 가져온 데이터를 설정하는 클래스

```java
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private  String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");
    }

    public String getSecretKey() {
        return secretKey;
    }
}
```

### FormWebAuthenticationDetailsSource

```java
@Component
public class FormWebAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest request) {
        return new FormWebAuthenticationDetails(request);
    }
}
```

- WebAuthenticationDetails를 생성하는 클래스
- 설정클래스이기 때문에 Bean 등록

### SecurityConfig

```java
@Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // 권한 부여
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
// 추가
                .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                .defaultSuccessUrl("/")
                .permitAll();
}

<input type="hidden" th:value="secret" name="secret_key" />
```

- secretKey 검증 추가를 위해 `CustomAuthenticationProvider` 추가

### CustomAuthenticationProvider

```java
@Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 검증을 위한
        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        // 추가 검증을 위해 UserDetails를 반환한다.
         AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(loginId);

        if (!passwordEncoder.matches(password, accountContext.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        String secretKey = ((FormWebAuthenticationDetails) authentication.getDetails()).getSecretKey();
        if (secretKey == null || !"secret".equals(secretKey)) {
            throw new IllegalArgumentException("Invalid Secret");
        }

        return new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }
```

---

# # 09. 인증 성공 핸들러 - CustomAuthenticationSuccessHandler

- 인증에 성공한 이후에 후속작업을 위한 successHandler

### CusomAuthenticationSuccessHandler

```java
@Component
public class FormAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

// 사용자의 이전 접근 기억 참고
    private RequestCache requestCache = new HttpSessionRequestCache();

// 실제 이동을 위한 객체
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException {

        setDefaultTargetUrl("/");

// 사용자가 거처온 위치를 알기 위해서 == 요청 정보
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if(savedRequest!=null) {
// 이전의 요청 url이 있다
            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, targetUrl);
        } else {
// 인증 이전에 예외가 발생했다면?
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
```

### SecurityConfig

```java
@Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // 권한 부여
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                .defaultSuccessUrl("/")
// 성공 시 핸들러 추가
                .successHandler(customAuthenticationSuccessHandler)
                .permitAll();
}
```

---

# # 10. 인증 실패 핸들러 - CustomAuthenticationFailureHandler

- AuthenticationProvider, UserDetailsService 등에서 인증에 실패했을 경우, onAuthenticationFailure가 실행된다.
- 클라이언트에게 오류 보여주기

### CustomAuthenticationFailureHandler

```java
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = "Invalid Username or Password";

        if (exception instanceof BadCredentialsException){
            errorMessage = "Invalid Username or Password";
        }else if (exception instanceof InsufficientAuthenticationException){
            errorMessage = "Invalid Secret Key";
        }

        setDefaultFailureUrl("/login?error=true&exception="+exception.getMessage());

        super.onAuthenticationFailure(request, response, exception);
    }
}

```

### InsufficientAuthenticationException?

```java
public class InsufficientAuthenticationException extends AuthenticationException {
    public InsufficientAuthenticationException(String msg) {
        super(msg);
    }

    public InsufficientAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }
}
```

- AuthenticationException을 상속받은 객체
- **우리 코드에 적용 가능하다.**

### FormAuthenticationProvider

- 예외가 넘어오는 곳

```java
@Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 검증을 위한
        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        // 추가 검증을 위해 UserDetails를 반환한다.
         AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(loginId);

        if (!passwordEncoder.matches(password, accountContext.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        String secretKey = ((FormWebAuthenticationDetails) authentication.getDetails()).getSecretKey();
        if (secretKey == null || !"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("Invalid Secret");
        }

        return new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }
```

### LoginController

```java
@RequestMapping(value="/login")
	public String login(@RequestParam(value = "error", required = false) String error,
						@RequestParam(value = "exception", required = false) String exception, Model model){
		model.addAttribute("error",error);
		model.addAttribute("exception",exception);
		return "login";
	}
```

### SecurityConfig

```java
@Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // 권한 부여
								// 경로에 접근이 가능하도록 한다.
								.antMatchers("/", "/users", "/user/login/**", "/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll();
}
```
