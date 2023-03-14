# 스프링 시큐리티 기본 API 및 Filter 이해

---

---

## 스프링 시큐리티 의존성 추가시 일어나는 일

---

별도의 설정 없이 [웹 보안 기능 → 현재 시스템] 적용

1. 모든 요청은 인증이 되어야 요청 가능
2. 폼 로그인 / httpBasic 로그인 방식
3. 기본 로그인 페이지 제공
4. 기본 계정 1개 - console에 찍혀있음

현재 없는 기능

- 계정 추가
- 권한 추가
- DB연동 기능

## 사용자 정의 보안기능 구현

---

### (~~WebSecurityConfigurerAdapter)~~SecurityFilterChain와 HttpSecurity

(~~WebSecurityConfigurerAdapter)~~`SecurityFilterChain`

- deprecated 되어 3.0 버전에서는 사용불가, SecurityFilterChain 활용
- 웹 보안기능 초기화 및 설정 역할

`HttpSecurity`

- 세부 보안 기능을 설정 가능 API 제공
- 기능들
    
    ![Untitled](https://user-images.githubusercontent.com/57485510/224981391-cf12100c-9906-4613-907b-fe0f76bda5ce.png)
    

설정을 해보자

- user/pasword 커스텀 적용
    
    ```yaml
    spring:
      security:
        user:
          name: user
          password: rlagidrl1
    ```
    
- SpringSecurity Config java
    
    ```java
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {
    
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
            http.authorizeHttpRequests()
                    .anyRequest().authenticated();
            http.formLogin();
    
            return http.build();
        }
    }
    ```
    

### 로그인 처리 방식

1. /home 요청
2. 인증 안된 요청 리다이렉트로 로그인 창 이동
3. POST user/pwd
4. 세션 및 인증토큰 생성/저장
5. 세션에 저장된 인증토큰으로 /home요청 다시

### Form Login 인증 API 구성

![Untitled 1]

- 직접 만들어보면서 확인

## 인증 API - 로그인 폼 인증

---

### 인증 FLOW
![Untitled 2](https://user-images.githubusercontent.com/57485510/224981310-95ac0d3f-81e5-4011-9a4c-dcb89f514984.png)


- `AuthPathRequestMatcher`(/login)와 `Authentication`은 인증하기 전에 처리되는 로직
    1. 요청 정보가 매핑 되는지 보고
    2. 요청보에서 username과 password로 `Authentication`객체에 담는다.
- `AuthenticaionManager`는 실제 인증 역할
    - 내부에 `AuthenticationProvider`객체들 중에 선택해서 → 인증을 위임받음
        - 인증실패/성공 여부를 나타냄 → 실패 시 `AuthenticationException`
        - 성공 시, `Authentication` 객체를 만들어, 인증에 성공한 결과(user, authorities..) 저장
    - `AuthenticationProvider`로부터 받은 `Authentication`을 반환
        - 그 안에 `User`객체와 `Authorities` 객체가 담김
- `SecurityContext`
    - `Authentication`객체를 저장하는 객체

### FilterChainProxy

- 등록된 filter를 순서대로 처리해주는 객체
- 리스트 순서로 처리한다

## Logout과 LogoutFilter

---

세션 무효화, 인증토큰 삭제, 인증토큰이 저장되어있는 `SecurityContext`객체, 쿠키정보 삭제, 로그인 페이지 리다이렉트

### http.logout()

- 로그아웃 처리
    ![Untitled 3](https://user-images.githubusercontent.com/57485510/224981320-65765aa4-48a4-4c53-a688-67ce92c2478b.png)
    
    

### Logout FLOW

- 이미지
    
    ![Untitled 4](https://user-images.githubusercontent.com/57485510/224981330-6b1235e5-710b-4ae0-a1fb-55bcf134329c.png)

## Remember me

---

세션이 만료되고 웹 브라우저가 종료된 후에도, 애플리케이션이 사용자를 기억하는 기능( ex: 쇼핑몰 - 아이디 기억하기)

remember-me 쿠키에 대한 HTTP 요청을 확인 → 토큰 유효성 검사 + 토큰 검증 → 사용자 로그인

### 사용자 라이프 사이클

- 인증 성공([remember-me 쿠키] 설정)
- 인증 실패([remember-me 쿠키] 존재 ⇒ [remember-me 쿠키] 무효화)
- 로그아웃( [remember-me 쿠키] ⇒ [remember-me 쿠키] 무효화)

### Remember-me 인증 API
![Untitled 5](https://user-images.githubusercontent.com/57485510/224981333-5e36eab3-0adb-44d7-b891-bfeb6cee990b.png)

### 원리

1. remember-me를 설정 → remember-me 쿠키 설정
2. remember-me 쿠키 ✅ JSESSIONID 쿠키 [삭제]
3. remember-me 쿠키를 통해 `SecurityContext`에서 인증정보를 가지고 JSESSIONID 재발급

Remember-me FLOW

![Untitled 6](https://user-images.githubusercontent.com/57485510/224981338-c49035d9-e4b8-4f3f-8f0c-f82f0202eb4d.png)

- 세션이 만료되었거나, 브라우저가 종료되었을 때 세션이 끊긴 경우 ⇒ 인증을 유지하기 위해서 RememberMeAuthenticationFilter가 동작
    1. `Authentication` 객체가 null인 경우(없는경우)
    2. Remember-me 쿠키가 헤더에 담겨있는 경우

실제 remember-me 로직이 도는 클래스 (RememberMeServices 구현체)

- `TokenBasedRememberMeService` → 토큰 기반
- `PersistentTokenBasedRememberMeServices` → DB에 저장하여 사용

## AnnoymousAuthenticationFilter

---

인증받은 사용자와 구분해서 처리하기 위한 용도로 `Authentication`이 아니면 (떨구던 기존방식과는 다르게) `AnonyousAuthenticationFilter`를 적용한다

- 권한 또한 `ROLE_ANONYMOUS`를 부여가능
- 화면에서 인증여부 구현할 때도, `isAnonymous()`와 `isAuthenticated()` 로 구분하여 사용
- `createAuthentication()` → `new AnonymousAuthenticationToken`을 만들어서 `setDetails` 해준다
- 다만, Anonymous 설정을 했음에도, `AnonymousAuthenticationToken` 자체가 없으면 exception을 던진다.
- 

## 동시세션제어 / 세션고정보호 / 세션정책

---

### 동시세션제어

![Untitled 7](https://user-images.githubusercontent.com/57485510/224981341-db2aa023-0095-45d8-b232-b1c677ac7e88.png)

**최대 세션 허용 개수 초과(1개가정)**

1. 이전 사용자 세션 만료
    - 최대 세션 허용 개수를 넘기면, 2번째 사용자를 위해 1번째 사용자 세션 만료를 설정
    - 즉, 이 상황에서 1번 사용자는 세션 만료
2. 현재 사용자 인증 실패
    - 2번째 사용자 위치에서 로그인을 시도하면 인증 예외 발생
- 동시세션 제어 API
    
    ![Untitled 8](https://user-images.githubusercontent.com/57485510/224981346-579f00de-aebc-4a59-b7fd-4d5959802e7d.png)
    

### 세션고정보호


![Untitled 9](https://user-images.githubusercontent.com/57485510/224981353-ccac96be-d29a-4961-9275-8c78c7cdd3d2.png)

공격자가 심어놓은 세션ID로 로그인을 시도하도록 유도

해결방법

- 인증을 거칠 때마다 새로운 세션 ID를 발급하도록 설정 ← 기본적으로 시큐리티가 설정해놓음
    
    ![Untitled 10](https://user-images.githubusercontent.com/57485510/224981357-ee9137b8-eb92-4f77-91a8-7696fc356c0d.png)
    
    → `migrateSession`은 Servlet 3.1이하에서 기본값이었음
    

`none` 테스트 결과

- 사파리 브라우저 JSESSIONID를 → 크롬 브라우저 JSESSIONID에 설정
- 크롬 브라우저 로그인
- 사파리 브라우저 root (/) 페이지에 접근
- 접근 성공됨

### 세션정책

- 세션 정책API
    
    ![Untitled 11](https://user-images.githubusercontent.com/57485510/224981361-08149be4-ec04-48b9-b167-e9e088446c80.png)
    
    `SessionCreationPolicy.Always` : 항상 세션 생성
    
    `SessionCreationPolicy.If_Required` : 필요시 생성
    
    `SessionCreationPolicy.Never` : 생성하지 않지만 이미 존재하면 사용
    
    `SessionCreationPolicy.Stateless` : 세션을 생성하지 않는 `JWT`같은 것을 사용
    

## 세션 제어 필터

---

### SessionManagementFilter

기능 (바로 위 테스트 했던 부분)

- 세션 관리
- 동시적 세션 제어
- 세션 고정 보호
- 세션 생성 정책

### ConcurrentSessionFilter

- 매 요청마다 현재 사용자 세션 만료 체크
    - 만료되면 즉시 만료
    - session.isExpired() == true ← 즉시 로그아웃 처리, 즉시 오류 페이지 응답

### 세션 제어 필터 FLOW

- 이미지
    
    ![Untitled 12](https://user-images.githubusercontent.com/57485510/224981363-0dd27b2a-ee5b-4f40-93bb-5f9737ce0163.png)
    
    - 세션만료에 대한 여부 체크를 SessionManagementFilter를 통해 확인하고 로그아웃 처리를 진행

### SessionManagementFilter를 활용하는 Sequence Diagram

- `ConcurrentSessionControlAuthenticationStrategy`, `ChangeSeesionIdAuthenticationStrategy`, `RegisterSessionAuthenticationStrategy` 정상 처리 과정
    
    ![Untitled 13](https://user-images.githubusercontent.com/57485510/224981370-8cb29bbc-ef0b-4ad4-94d6-5c986451a26f.png)
    
    - → User1의 정상 처리 로직을 나타낸다
- User1과 같은 사용자 정보를 가지는 User2의 인증 실패인 경우
    
    ![Untitled 14](https://user-images.githubusercontent.com/57485510/224981375-2a4ab2bf-60f4-4be5-9ebc-e73bcaf281b7.png)
    
    - User2가 (1) 세션에 대한 예외를 던지는 방식, (2) User1의 세션을 만료시키고, User2의 세션을 연결하는 전략

## 권한 설정 및 표현식

---

### 선언적 방식

URL

- `http.antmatchers(”/users/**”).hasRole(”USER”)`

Method

```java
@PreAuthorize(”hasRole(’USER’)”)
public void user(){
		System.out.println("user");
}
```

- `PreAuthorize(..)` 이부분이 선언적 방식을 의미

### 동적 방식

URL, Method + DB 연동을 통해 활용

### 권한 설정 및 API 표현식

권한 설정 

![Untitled 15](https://user-images.githubusercontent.com/57485510/224981377-a461be09-60d1-4f67-a781-97cd64959e1b.png)

- 큰 범위의 경로가 뒤에 와야, **세부 정보가 위에서 먼저 보안 검사**를 마치고 뒤로 넘어갈 수 있다

인가 API - 표현식

![Untitled 16](https://user-images.githubusercontent.com/57485510/224981380-ab6120e9-fc6b-4dc3-83f1-3a7d3ef89d46.png)

- `hasRole(”USER”)` ==  `hasAuthority(”ROLE_USER”)` : 즉, prefix로 ROLE을 붙이는지 안 붙이는지

실제 URL 별로 ROLE에 해당하는 접근 제한을 코드로 확인해보자

```java
// 유저 설정
@Bean
public InMemoryUserDetailsManager userDetailsService() {
    UserDetails user1 = User.withDefaultPasswordEncoder()
            .username("user")
            .password("1111")
            .roles("USER")
            .build();

    UserDetails user2 = User.withDefaultPasswordEncoder()
            .username("admin")
            .password("1111")
            .roles("ADMIN")
            .build();

    UserDetails user3 = User.withDefaultPasswordEncoder()
            .username("sys")
            .password("1111")
            .roles("SYS")
            .build();
    return new InMemoryUserDetailsManager(user1, user2, user3);
}

// URL 제한 config
http
        .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").hasRole("USER")
                .requestMatchers("/admin/pay").hasRole("ADMIN")
                .requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                .anyRequest().authenticated());
```

- `USER` → `/user`에만 접근 가능
- `ADMIN` → `/admin/**` 모두 접근 가능
- `SYS` → `/admin/pay` (제한 우선순위로 인해)을 제외하고 `/admin/**`에 접근가능

> 참고: 강의에서는 ****WebSecurityConfigurerAdapter****를 사용해서 현재 Springboot 3.0 설정과는 강의내용과 다르다 → github을 확인할 것
> 

## 인증/인가 API

---

### ExceptionTranslationFilter

하위 예외들은 누가 exception을 throw할까? → `FilterSecurityInterceptor` (보안 필터 중 맨 마지막에 위치)

**AuthenticationException - 인증 예외 처리**

- `AuthenticationEntryPoint`를 호출 → 로그인 페이지 or 401에러 전달
- 인증예외 발생 전의 요청 정보를 저장
    - `RequestChache` - [사용자의 이전 요청 정보]를 세션에 저장히고 이를 꺼내는 캐시 메커니즘 ← 세션에 저장하는 곳
    - `SavedRequest` - 사용자가 요청한 [request param, 헤더값] 저장 ← 요청정보를 저장하는 곳

**AccessDeniedException - 인가 예외 처리**

- `AccessDeniedHandler`에서 예외처리 제공

### ExcptionTranslationFilter FLOW

![Untitled 17](https://user-images.githubusercontent.com/57485510/224981384-53f17f1c-2502-46ed-becd-c6955e2e76bf.png)

- `FilterSecurityInterceptor`에서는 인증 예외는 안하고, 인가 예외로 간다
    - 상황: 익명 or 리멤버미 의 경우일 때
    - 순서: `FilterSecurityInterceptor` → `ExceptionTranslationFilter` → `AccessDeniedException` → `AuthenticationException`
- 예외가 발생하면 `AuthenticationException`은 다음과 같이 행동
    1. `response.redirect`로 `/login`에 보내기
    2. `HttpSessionRequestCache`에 [사용자 요청 정보] 저장
- 그럼 인가 예외는 언제??
    - `/user`로 접근한 admin 권한의 사용자가 USER 역할에만 접근가능한 기능에 접근이 불가할 때 `AccessDeniedHandler`로 간다
- API
    
    ![Untitled 18](https://user-images.githubusercontent.com/57485510/224981388-9360b45e-bc11-4b6a-80b0-93cc6ea35888.png)
    
    - 밑에 accessDeniedHandler는 “인가 실패 처리”가 맞다

### RequestCacheAwareFilter

## 사이트 간 요청 위조

---

### Form 인증 - CsrfFilter

모든 요청에 랜덤한 값으로 생성된 토큰을 HTTP 파라미터로 요구 → 클라이언트 토큰 ↔ 서버 토큰 비교

- 일치하지 않으면 요청 실패
- 토큰이 일치하지 않는 것은, 공격자 사이트에서 요청하는 HTTP 통신을 거를 수 있다
- <input type=”hidden”… >으로 토큰을 넘김

back: 2983 → 11818

front: 3189 → 12153