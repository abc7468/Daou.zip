## 프로젝트 구성
- maven, spring boot 2.5.7, java 11
- 최근 구성과 다른점이 있어 강의 기반으로 따라감.
- Spring Security 의존성 추가

````
<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
</dependency>
````

<img src="https://user-images.githubusercontent.com/60870438/224699837-e7e23593-4404-45ac-b56c-90b53b07c933.png" width="70%" >

- 현재는 WebSecurityConfigurerAdapte가 deprecated되어 SecurityFilterChain을 Bean으로 등록시켜 configure 메서드를 사용한다.
- WebSecurityConfigurerAdapter
  - 시큐리티 웹 보안 기능 초기화 및 설정 작업
- HttpSecurity
  - 세부적인 보안 기능을 설정할 수 있는 API를 제공한다.
  - 인증/인가에 대한 API 제공

- application.properties에서 기본 계정을 설정할 수 있다.
```
spring.security.user.name={userId}
spring.security.user.password={password}
```

# Form Login 인증

```
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated(); // 요청에 대한 인가 등록
        http
                .formLogin() // form login 방식 사용
                .loginPage("/loginPage") // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/") // 로그인(인증) 성공 후 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // 아이디 파라미터명
                .passwordParameter("passwd") // 패스워드 파라미터명
                .loginProcessingUrl("/login_proc") // 로그인 시도하는 곳. 기본은 /login -> 로그인 Form의 Action Url
                .successHandler(new AuthenticationSuccessHandler() { // 로그인 성공 후, 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication = " + authentication.getName()); // 인증에 성공한 사용자 이름
                        response.sendRedirect("/"); // 리다이렉트
                    }
                })
                .failureHandler(new AuthenticationFailureHandler(){ // 로그인 실패 후 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        System.out.println("exception = "+e);
                        response.sendRedirect("/login");
                    }
                })
                .permitAll();
    }
}
```

<img src="https://user-images.githubusercontent.com/60870438/224759446-1f835ab6-9a8e-45da-a923-751fc07674ee.png" width="50%" >

### 💡 defaultSuccessUrl과 successhander의 차이는 뭘까?

- SpringSecurity는 인증이 필요한 페이지에 사용자가 접근하면, 로그인 페이지로 이동시킨다.
- 로그인이 성공하면 사용자가 처음에 접근했던 페이지로 리다이렉트 시킨다.

- defaultSuccessUrl: 로그인 하기 전 방문한 페이지가 아닌 무조건 해당 url로 반환한다.
- successForwardUrl: 특정 url을 호출해 다른 로직을 한 번 더 실행하도록 한다.
- successHandler: successForward와 비슷하게 controller로 분리된 로직을 config에서 한번에 처리할 수 있게 한다.

[인증 성공 시, 이동 참고](https://twer.tistory.com/entry/Spring-Security-defaultSuccessUrl-successForwardUrl-successHandler)

# UsernamePasswordAuthenticationFilter 동작 방식

<img src="https://user-images.githubusercontent.com/60870438/224763404-8e9a9e7f-3731-4493-83d8-8df95e9747c7.png" width="70%" >

### 🎈 FilterChainProxy

<img src="https://user-images.githubusercontent.com/60870438/224763751-6eb1373e-b3a7-4c5b-a8e7-8c329ce74ce5.png" width="70%" >

- filter를 관리하는 Bean
- security가 초기화되며 기본 필터와 config 파일에 설정한 필터가 들어간다
- 설정한 필터는 UsernamePasswordAuthenticationFilter 이후에 실행된다.

<img src="https://user-images.githubusercontent.com/60870438/224770175-7b510257-22de-41f4-aceb-e7dc026eae78.png" >

# Logout

<img src="https://user-images.githubusercontent.com/60870438/225357702-c6e3d644-bb2b-4cc8-87b8-6ae35351c6ce.png" width="70%" >

### Logout 동작 방식

<img src="https://user-images.githubusercontent.com/60870438/225360754-94f07e6e-322d-4684-8955-f765235b7aeb.png" width="50%">

<img src="https://user-images.githubusercontent.com/60870438/225363803-dbce701f-f0fd-4269-98e7-124f0d79ee08.png" >

# Remember Me

1. 세션이 만료되고 웹 브라우저가 종료된 후에도 애플리케이션이 사용자의 계정을 기억하는 기능
2. Remember-Me 쿠키에 대한 Http 요청을 확인한 후, 토큰 기반 인증을 사용해 유효성을 검증하면, 로그인이 이루어진다.
3. 사용자 라이프 사이클
            - 인증 성공 (remember-me 쿠키 설정)
            - 인증 실패 (쿠키 존재시, 쿠키 무효화)
            - 로그아웃 (쿠키 존재시, 쿠키 무효화)

<img src="https://user-images.githubusercontent.com/60870438/225365993-8d26bec6-fbde-4f12-bd28-f3d573601adb.png" width="70%">

- tokenValiditySeconds: 초 단위로 기간 설정
- alwaysRemember: true가 되면 활성화하지 않아도 항상 실행된다. 즉, 인증하면 무조건 실행
- userDetailsService: 시스템에 있는 사용자 계정 관리

### 세션 인증 과정
1. 서버는 클라이언트에게 인증에 성공한 세션 ID를 반환
2. 클라이언트는 이후 요청 헤더에 세션 ID를 담아 보냄
3. 요청 받은 서버는 세션 ID와 매칭되는 세션을 꺼내 인증 객체 반환

<img src="https://user-images.githubusercontent.com/60870438/225367153-99abec18-4aed-4ecd-a06c-c25cb1a59035.png" width="70%">

- 세션 ID가 없어도 remember-me 쿠키로 인증 가능

# RememberMeAuthenticationFilter

- 실행 조건
1. Autehntication 인증 객체가 null인 경우
            - SecurityContext가 null인 경우 == 인증되지 않은 사용자일 경우,
            - 사용자의 세션이 만료된 경우,
            - 세션이 없는 경우,
2. remember-me 쿠키가 있는 경우

<img src="https://user-images.githubusercontent.com/60870438/225371074-25c972d0-8fc0-4b1d-85fe-1bd41f5f3d0d.png" width="70%">

- RememberMeService의 구현체
            - Token..: 메모리 vs 요청 토큰 / 약 14일 유지
            - Persist..: DB vs 요청 토큰 / 영구적


