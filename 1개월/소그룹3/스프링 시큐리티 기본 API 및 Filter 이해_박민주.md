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

![image](https://user-images.githubusercontent.com/60870438/224699837-e7e23593-4404-45ac-b56c-90b53b07c933.png)
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

## Form Login 인증

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

![image](https://user-images.githubusercontent.com/60870438/224759446-1f835ab6-9a8e-45da-a923-751fc07674ee.png)

#### 💡 defaultSuccessUrl과 successhander의 차이는 뭘까?

- SpringSecurity는 인증이 필요한 페이지에 사용자가 접근하면, 로그인 페이지로 이동시킨다.
- 로그인이 성공하면 사용자가 처음에 접근했던 페이지로 리다이렉트 시킨다.

- defaultSuccessUrl: 로그인 하기 전 방문한 페이지가 아닌 무조건 해당 url로 반환한다.
- successForwardUrl: 특정 url을 호출해 다른 로직을 한 번 더 실행하도록 한다.
- successHandler: successForward와 비슷하게 controller로 분리된 로직을 config에서 한번에 처리할 수 있게 한다.

[인증 성공 시, 이동 참고](https://twer.tistory.com/entry/Spring-Security-defaultSuccessUrl-successForwardUrl-successHandler)

### UsernamePasswordAuthenticationFilter

![image](https://user-images.githubusercontent.com/60870438/224763404-8e9a9e7f-3731-4493-83d8-8df95e9747c7.png)

#### 🎈 FilterChainProxy

![image](https://user-images.githubusercontent.com/60870438/224763751-6eb1373e-b3a7-4c5b-a8e7-8c329ce74ce5.png)

- filter를 관리하는 Bean
- security가 초기화되며 기본 필터와 config 파일에 설정한 필터가 들어간다
- 설정한 필터는 UsernamePasswordAuthenticationFilter 뒤에 들어간다.

![image](https://user-images.githubusercontent.com/60870438/224770175-7b510257-22de-41f4-aceb-e7dc026eae78.png)

