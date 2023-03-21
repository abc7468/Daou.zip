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

``` java
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

</br></br></br>
# UsernamePasswordAuthenticationFilter 동작 방식

<img src="https://user-images.githubusercontent.com/60870438/224763404-8e9a9e7f-3731-4493-83d8-8df95e9747c7.png" width="70%" >

### 🎈 FilterChainProxy

<img src="https://user-images.githubusercontent.com/60870438/224763751-6eb1373e-b3a7-4c5b-a8e7-8c329ce74ce5.png" width="70%" >

- filter를 관리하는 Bean
- security가 초기화되며 기본 필터와 config 파일에 설정한 필터가 들어간다
- 설정한 필터는 UsernamePasswordAuthenticationFilter 이후에 실행된다.

<img src="https://user-images.githubusercontent.com/60870438/224770175-7b510257-22de-41f4-aceb-e7dc026eae78.png" >

</br></br></br>
# Logout

<img src="https://user-images.githubusercontent.com/60870438/225357702-c6e3d644-bb2b-4cc8-87b8-6ae35351c6ce.png" width="70%" >

### Logout 동작 방식

<img src="https://user-images.githubusercontent.com/60870438/225360754-94f07e6e-322d-4684-8955-f765235b7aeb.png" width="50%">

<img src="https://user-images.githubusercontent.com/60870438/225363803-dbce701f-f0fd-4269-98e7-124f0d79ee08.png" >

</br></br></br>
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

</br></br></br>
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

### remember-me cookie 인증 과정

<img src="https://user-images.githubusercontent.com/60870438/225375596-4eb7a7dc-567e-4925-9c51-8a13665e841b.png">

</br></br></br>
# 익명 사용자 (AnonymousAuthenticatioFilter)

- 익명과 인증 사용자 구분을 위해 사용
- 인증 객체를 세션에 저장하지 않는다. 하지만 SecurityContext에 익명 인증 객체를 생성하긴 한다.

</br></br></br>
# 세션 제어

## 동시 세션 제어 

<img src="https://user-images.githubusercontent.com/60870438/225377211-126dda94-7685-4662-9c9b-df643905167c.png" width="70%">

1. 이전 사용자의 세션 만료
2. 현재 사용자의 인증 실패

<img src="https://user-images.githubusercontent.com/60870438/225376264-8bc4fdb6-a0e2-40e5-a110-7404e5a2eb9e.png" width="70%">

## 세션 고정 보호

<img src="https://user-images.githubusercontent.com/60870438/225377357-b6b3c190-2057-4389-ba3b-b506e80205b6.png" width="70%">

- 같은 쿠키를 공유하면서 생기는 문제
- 세션값으로 인증받은 객체를 사용할 수 있기 때문이다. 이를 방지하기 위해 spring security가 제공하는 기능
- 인증할 때마다 새로운 세션, 쿠키를 생성한다.

<img src="https://user-images.githubusercontent.com/60870438/225377732-c053977f-a5d8-4c04-9e45-a36f812cd77e.png" width="70%">

- changeSessionId()
            - default: 세션 유지, 아이디 생성
            - none: 세션 고정
            - migrateSession: 세션, 아이디 생성 3.1이하 (세션 설정 유지)
            - newSession: 세션, 아이디 새로 생성


## 세션 정책

<img src="https://user-images.githubusercontent.com/60870438/225378734-40088c56-66c1-4e88-9ef6-67959b689e73.png" width="70%">

</br></br></br>
# 세션 제어 필터

## `SessionManagementFilter`
1. 세션 관리: 인증 시, 세션정보 등록,조회,삭제 등 이력 관리
2. 동시 세션 제어: 동일 계정, 최대 접근 세션 수 제한
3. 세션 고정 보호: 인증시마다 세션 쿠키 새로 발급해 쿠키 조작 방지
4. 세션 생성 정책

## `ConcurrentSessionFilter`
- 매 요청마다 현재 사용자의 세션 만료 여부 체크
- 즉시 만료 처리 -> 로그아웃 -> 즉시 오류 페이지 응답

- 두 필터 모두, 동시 세션 제어를 위해 연계되어 사용된다.

</br>
<img src="https://user-images.githubusercontent.com/60870438/225380431-a34c795a-5790-487d-a993-9a65745d1e31.png" width="70%">

- 최대 세션 접근 개수 초과시, 발생하는 과정

<img src="https://user-images.githubusercontent.com/60870438/225380731-aa638d6b-e8ff-404c-aff9-1ca53e880d07.png" >

</br></br></br>
# 권한 설정과 표현식

## 권한 설정

1. 선언적 방식
- url
`http.antMatchers(”*/users/**”).hasRole(”USER”)`
- method
```java
@PreAuthorize(”hasRole(’USER’)”)
public void user() { System.out.println(”user”) };c void user() { System.out.println(”user”) };
```

2. 동적 방식 - DB 연동 프로그래밍
- url
- method

<img src="https://user-images.githubusercontent.com/60870438/225381925-f0e3b770-aa2e-4e7d-a0c9-4f94b036e6db.png" width="70%">
- /shop/**: 해당 경로로 접근할 때만, 보안 검증이 이루어진다.
- `antMatchers(url).{권한 정보}`
- .access를 사용하면 spEL 문법을 활용할 수 있다.
- 좁고 구체적인 범위부터 확장해나간다.

## 표현식

<img src="https://user-images.githubusercontent.com/60870438/225382592-c283252d-ee1a-4b7c-aceb-f055b58744c3.png" width="70%">

- anonymous()에는 user가 접근 가능하다? NO
- hasRole에는 "ROLE_" 접두사가 붙으면 안된다.
- hasAuthority에는 "ROLE_" 접두사가 붙어야한다.
