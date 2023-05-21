# 5. 인가 프로세스 DB 연동 웹 계층 구현

---

# #01. 스프링 시큐리티 인가 개요

- DB와 연동하여 자원 및 권한을 설정하고 제어함으로 동적 권한 관리가 가능하도록 한다,
- 설정 클래스 소스에서 권한 관련 코드 모두 제거
    - ex) antMatcher(”/user”).hasRole(”USER”)
- 관리자 시스템 구축
    - 회원 관리 - 권한 부여
    - 권한 관리 - 권한 생성, 삭제
    - 자원 관리 - 자원 생성, 삭제, 수정 권한 매핑
- 권한 계층 구현
    - URL - Url 요청시 인가 처리
    - Method - 메소드 호출 시 인가 처리
        - Method
        - Poincut

---

# #02. 관리자 시스템 - 권한 도메인, 서비스, 리포지토리 구현

> Url 방식
> 
- 현재는 설정 클래스에서 antMatcher를 사용하고 있다.
    
    ```java
    .antMatchers("/mypage").hasRole("USER")
                    .antMatchers("/messages").hasRole("MANAGER")
                    .antMatchers("/config").hasRole("ADMIN")
    ```
    

- 현재 도메인 관계도
    
![image](https://github.com/abc7468/Daou.zip/assets/60870438/73392bc8-efe5-431b-abb3-2c21ff1fae20)
    
- 테이블 관계도
    
![image](https://github.com/abc7468/Daou.zip/assets/60870438/f00cbf5f-7dbc-4736-9251-c61bd28ab4cc)

## 도메인

### Account

```java
@Entity
@Data
@ToString(exclude = {"userRoles"})
@Builder
@EqualsAndHashCode(of = "id")
@NoArgsConstructor
@AllArgsConstructor
public class Account implements Serializable {

    @Id
    @GeneratedValue
    private Long id;

    @Column
    private String username;

    @Column
    private String email;

    @Column
    private int age;

    @Column
    private String password;

    @ManyToMany(fetch = FetchType.LAZY, cascade = {CascadeType.ALL})
    @JoinTable(name = "account_roles", joinColumns = {@JoinColumn(name = "account_id")}, inverseJoinColumns = {
            @JoinColumn(name = "role_id")})
    private Set<Role> userRoles = new HashSet<>();
}
```

### Role

```java
@Entity
@Table(name = "ROLE")
@Getter
@Setter
@ToString(exclude = {"users","resourcesSet"})
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class Role implements Serializable {

    @Id
    @GeneratedValue
    @Column(name = "role_id")
    private Long id;

    @Column(name = "role_name")
    private String roleName;

    @Column(name = "role_desc")
    private String roleDesc;

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "roleSet")
    @OrderBy("ordernum desc")
    private Set<Resources> resourcesSet = new LinkedHashSet<>();

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "userRoles")
    private Set<Account> accounts = new HashSet<>();

}
```

### Resources

```java
@Entity
@Table(name = "RESOURCES")
@Data
@ToString(exclude = {"roleSet"})
@EntityListeners(value = { AuditingEntityListener.class })
@EqualsAndHashCode(of = "id")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Resources implements Serializable {

    @Id
    @GeneratedValue
    @Column(name = "resource_id")
    private Long id;

    @Column(name = "resource_name")
    private String resourceName;

    @Column(name = "http_method")
    private String httpMethod;

    @Column(name = "order_num")
    private int orderNum;

    @Column(name = "resource_type")
    private String resourceType;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "role_resources", joinColumns = {
            @JoinColumn(name = "resource_id") }, inverseJoinColumns = { @JoinColumn(name = "role_id") })
    private Set<Role> roleSet = new HashSet<>();

}
```

---

# #03. 웹 기반 인가처리 DB 연동 - 주요 아키텍처 이해

> 주요 아키텍처
> 

- 스프링 시큐리티의 인가처리
- `http.antMatchers(”/user”).access(”hasRole(’USER’)”)`
- 사용자가 /user 자원에 접근하기 위해서는 ROLE_USER 권한이 필요하다.
    - 사용자: 인증 정보
    - /user: 요청 정보
    - ROLE_USER: 권한 정보
- 인가 처리를 담당하는 필터(`FilterSecurityInterceptor`)가 실제 인가 처리를 맡기는 곳은(`AccessDecisionManager`)그리고 이는 위의 세가지 정보를 전달 받아 인가처리를 진행한다.
- Filter가 세가지 정보를 전달하고 있다.

![image](https://github.com/abc7468/Daou.zip/assets/60870438/2c5856a3-3d6f-4f45-9fb9-c7c05433fd2e)

- `Authentication`은 SecurityContext 객체 안에 있다.
- `FilterInvocation`은 클래스의 객체를 생성해 request 정보를 저장해 전달한다.
- `List<ConfigAttribute>`: 권한 정보를 전달한다.
- 이를 `AccessDecisionManager`에게 전달한다.

- `http.antMatchers(”/user”).access(”hasRole(’USER’)”)`
    - 내부적으로 /user(자원정보)를 hasRole(’USER’)(권한정)와 매핑시킨다.
    - Filter가 자원에 해당하는 권한 정보를 Map에서 찾아 가져온다.
    - 전달 시 List<ConfigAttribute>로 담아 반환한다.
- vote(인증 정보, 요청 정보, 권한 정보)
- Mapping 시키는 클래스

### ExpressionBasedFilterInvocation..

- 초기화 중 Map 객체를 가지고 있다.
    
![image](https://github.com/abc7468/Daou.zip/assets/60870438/94753106-4212-494b-9291-a8ac714e5cc6)
    
- key는 ‘자원’ value는 ‘권한’ 형식으로 관리하고 있다.
    
![image](https://github.com/abc7468/Daou.zip/assets/60870438/f9b80859-bb47-4b1d-a41d-5de7f36f521b)
    

- Interceptor가 권한 정보를 요청한다
    
  ![image](https://github.com/abc7468/Daou.zip/assets/60870438/2792b4fa-2d1c-48cd-91f9-ce86d427c02b)
  - MetaDataSource에 초기화된 map 객체를 요청한다.
    
- 요청 정보와 match하는 정보가 있는지 찾고 있다.
    
![image](https://github.com/abc7468/Daou.zip/assets/60870438/4b0f3fe6-fe06-4f91-a253-51d507cea0c4)
    
- `ExpressionBasedFilterInvocationSecurityMetadataSource`와 `DefaultFilterInvocationSecurityMetadataSource`가 Filter 요청의 권한 목록을 반환하는 클래스
- 인증 정보는 SecurityContextHolder에서 찾아 온다.
    - 인증에 성공한 객체를 가져와 accessDecisionManager에게 인증, 요청, 권한 정보를 반환한다.
    - `decide(인증, 요청, 권한)`
- DB로 부터 map 정보를 가져올 수 있도록 바꿔보자.

![image](https://github.com/abc7468/Daou.zip/assets/60870438/1269d33b-3ed9-4c55-bebb-8aac350cf22b)

1. Filter: url 방식으로 인가 처리
2. Method: method 방식으로 인가 처리
    - 인터페이스 4개가 존재. 상단의 3개는 annotation 방식
    - `MapBasedMethod` 사용할 예정

### `DefaultFilterInvocation` → `ExpressionBasedFilterInvocation`

- 설정 클래스에서 표현식(antMatcher)로 설정한 인가 설정을 읽어들여 동작한다.

---

# #04. FilterInvocationSecurityMetadataSource (1)

- SecurityMetadataSource(최상위 클래스)
    
![image](https://github.com/abc7468/Daou.zip/assets/60870438/1778aaee-510c-4ee9-861f-d58359127f2d)
    
    3가지 메서드를 제공한다.
    
- 이를 상속한 FilterInvocationSecurityMetadataSource
    - url 방식으로 권한정보 관리
- UrlFilterInvocationSecurityMetadataSource로 만들어보자.
    - 사용자가 접근하고자 하는 Url 자원에 대한 권한 정보 추출
    - AccessDecisionManager에게 전달해 인가 처리 수행
    - DB로 부터 자원 및 권한 보를 매핑하여 맵으로 관리
    - 사용자의 매 요청마다 요청정보에 매핑된 권한 정보 확인

### 전체적인 흐름

![image](https://github.com/abc7468/Daou.zip/assets/60870438/dce4e241-5ebd-467f-9ec6-d12e47f27ec5)

1. /admin으로 접근
2. `FilterSecurityInterceptor`: 인가 처리 필터가 받는다. 권한 정보를 저회하기 위해 `MetadataSource` 호출
- `…MetadataSource`: requestMap(K: url 자원/V: 권한)을 가지고 있다.
    - DB에서 조회해 자원/권한 정보를 매핑해온다.
1. `MetadataSource`가 매치된 데이터(권한 목록)을 반환한다.
2. 권한 목록이 존재하면 AccessDecisionManager에게 전달
3. 권한 목록이 없다면 처리 없이 통과한다.

- AccessDecisionManager의 구현체
    - AffirmativeBased: 가장 보편
    - ConsensusBased
    - UnanimousBased

## UrlFilterInvocationSecurityMetadataSource

```java
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        // 파라미터가 object 인 이유는 url과 method 방식 둘다 사용될 수 있기 때문이다.
        HttpServletRequest request = ((FilterInvocation) object).getRequest();

        // 접근하고자 하는 요청 url의 권한 목록
        if (requestMap != null) {
            for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entries : requestMap.entrySet()) {
                RequestMatcher matcher = entries.getKey();
                // 요청 정보와 매칭하는지
                if (matcher.matches(request)) {
                    return entries.getValue();
                }
            }
        }
        return null;
    }

    // DefaultFilterInvocation에서 복사
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

}
```

## SecurityConfig

```java
// 추가
		@Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {

        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource2());
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        // 권한 필터는 인가 처리 전 인증 검사를 진행해야 한다.
        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
        return filterSecurityInterceptor;
    }

    @Bean
    public UrlFilterInvocationSecurityMetadataSource2 urlFilterInvocationSecurityMetadataSource2() {
        return new UrlFilterInvocationSecurityMetadataSource2();
    }

    private AccessDecisionManager affirmativeBased() {
        // 객체 만들 때, voter 여러개 전달 가능. 지금은 하나만
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
        return Arrays.asList(new RoleVoter());
    }

// configure 메소드에 http 추가
// FilterSecurityInterceptor 앞에 custom이 실행된다.
http
.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);
```

- 기존에는 표현식 추출해 설정하고 있다.
- customFilterInvocationSecurityMetadataSource 등록 후
    - 등록한 MetadataSource가 실행된다.
    - 처음 requestMap null return 시 권한에 대한 처리가 없는 것으로 본다.
    - 인가처리가 실행되지 않고 null이 리턴, 다음 필터로 간다.
    - 인증도 권한도 없지만 허가된다.
    - 이를 설정했을 때, antMatcher가 동작하지 않는 것을 볼 수 있음.
        - 한번 권한 체크를 했기 때문에 뒤의 FilterInvocation는 인가 처리를 하지 않는다.

---

# #05. FilterInvocationSecurityMetadataSource (2)

> Map 기반 DB 연동

![image](https://github.com/abc7468/Daou.zip/assets/60870438/34a3473e-3cd9-4fdf-887d-35fe7d7afbb7)

- DB에서 가져온 값을 ResourceMap에 저장한다. 이를 전달해 requestMap에 저장
- UrlResourcesMapFactoryBean
    - DB로 부터 얻은 권한/자원 정보를 ResourceMap을 빈으로 생성해 UrlFilterInvocationSecurityMetadataSoure에 전달한다.

## UrlResourceMapFactoryBean

```java
public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

    // DB로 부터 가져온 데이터 매핑
    private SecurityResourceService securityResourceService;
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap = new LinkedHashMap<>();

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {

        if (resourceMap == null) {
            init();
        }
        return resourceMap;
    }

    private void init() {
				// DB로 부터 매핑된 자원 얻
        resourceMap = securityResourceService.getResourceList();
    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    @Override
    public boolean isSingleton() {
        // 메모리에 하나만 존재하도록
        return FactoryBean.super.isSingleton();
    }
}
```

## SecurityResourceService

```java
public class SecurityResourceService {

    // 데이터 계층으로부터 데이터를 가져와야한다.
    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList(){
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();
        resourcesList.forEach(resources -> {
            List<ConfigAttribute> configAttributes = new ArrayList<>();
            resources.getRoleSet().forEach(role -> {
                configAttributes.add(new SecurityConfig(role.getRoleName()));
                result.put(new AntPathRequestMatcher(resources.getResourceName()), configAttributes);
            });
        });
        return result;
    }
}
```

## AppConfig

```java
@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository){
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository);
        return securityResourceService;
    }
}
```

## SecurityConfig

```java
// 연결
@Bean
    public UrlFilterInvocationSecurityMetadataSource2 urlFilterInvocationSecurityMetadataSource2() throws Exception {
        // Bean으로 생성된 DB에서 가져온 resourceMap을 전달한다.
				return new UrlFilterInvocationSecurityMetadataSource2(urlResourcesMapFactoryBean().getObject());
    }

private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
        return urlResourcesMapFactoryBean;
    }

// UrlFilterInvocationSecurityMetadataSources2에 추가
public UrlFilterInvocationSecurityMetadataSource2(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourcesMap) {
        this.requestMap = resourcesMap;
    }
```

---

# #06. 웹 기반 인가처리 실시간 반영하기

![image](https://github.com/abc7468/Daou.zip/assets/60870438/4d428b06-61cf-49f7-b0aa-29d29ca08ad8)

- 권한/자원 정보 업데이트 시 DB에 저장된 데이터가 map에 실시간으로 반영되어야 한다.
- 이전에는 null일 경우 init(), 한번 가져오면 같은 걸 썼다.

## UrlFIlterInvocationSecurityMetadataSource2

```java
// 메서드 추가
public void reload(){
        // 실시간으로 DB 정보가 반영된다.
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();
        Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();
        requestMap.clear();

        while (iterator.hasNext()){
            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
            requestMap.put(entry.getKey(), entry.getValue());
        }
    }
```

- ResourcesController에서 추가/삭제 시 `urlFilterInvocationSecurityMetadataSource2.reload();` 를 할 수 있도록 코드를 추가한다.

---

# #07. 인가처리 허용 필터 - PermitAllFilter 구현

- 인증 및 권한 심사를 할 필요가 없는 자원(/, /home, /login..) 들을 미리 설정해서 바로 리소스 접근이 가능하게 하는 필터

1. 내부 동작 원리

![image](https://github.com/abc7468/Daou.zip/assets/60870438/accd2613-bbcc-438d-a29f-7bc7c73eff88)

- `FilterSecurityInterceptor`은 요청을 받으면 `AbstractSecurityInterceptor`에게 인가 처리를 맡긴다.

2. 응용 동작 구현

![image](https://github.com/abc7468/Daou.zip/assets/60870438/44e65ecf-a4d7-41e8-88be-1033d5767dbb)

- 요청을 받으면 바로 인가처리를 맡기는 것이 아니라 로직이 추가된다.
- 인증/권한이 필요없는 자원을 저장해 request와 비교한다.
- 있을 경우 바로 권한 심사 없이 통과
- 없는 경우 실제 인가 처리를 하는 `AbstractSecurityInterceptor`에게 전달한다.

## PermitAllFilter

```java
public class PermitAllFilter extends FilterSecurityInterceptor {

    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private UrlFilterInvocationSecurityMetadataSource2 securityMetadataSource;
    private boolean observeOncePerRequest = true;

    private List<RequestMatcher> permitAllRequestMatcher = new ArrayList<>();

    public PermitAllFilter(String... permitAllResources) {

        for (String resource : permitAllResources) {
            // 인증/권한이 필요없는 자원 AntPathRequestMatcher 형태로 저장
            permitAllRequestMatcher.add(new AntPathRequestMatcher(resource));
        }
    }

    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {

        // 인가 처리 전, 먼저 permitAll을 위한
        boolean permitAll = false;
        // request 정보
        HttpServletRequest request = ((FilterInvocation) object).getRequest();

        for (RequestMatcher requestMatcher : permitAllRequestMatcher) {
            if (requestMatcher.matches(request)) {
                // 인가 처리 없이 통과
                permitAll = true;
                break;
            }
        }
        if (permitAll) {
            // return null이면 권한 심사를 하지 않는다.
            return null;
        }

        // 아니라면 부모클래스의 인가처리를 이어간다.
        return super.beforeInvocation(object);
    }

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        invoke(fi);
    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        if ((fi.getRequest() != null)
                && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
                && observeOncePerRequest) {
            // filter already applied to this request and user wants us to observe
            // once-per-request handling, so don't re-do security checking
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            // first time this request being called, so perform security checking
            if (fi.getRequest() != null && observeOncePerRequest) {
                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }

            // 이 곳에 들어가기 전 권한/인증이 필요없는 요청을 분리하자.

            InterceptorStatusToken token = super.beforeInvocation(fi);

            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, null);
        }
    }

    public boolean isObserveOncePerRequest() {
        return observeOncePerRequest;
    }

    public void setObserveOncePerRequest(boolean observeOncePerRequest) {
        this.observeOncePerRequest = observeOncePerRequest;
    }
}
```

## SecurityConfig

```java
private String[] permitAllResources = {"/", "/login", "/user/login/**"};

		@Bean
    public PermitAllFilter customFilterSecurityInterceptor() throws Exception {

//        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
				// 문자열 반환
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);
        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource2());
        permitAllFilter.setAccessDecisionManager(affirmativeBased());
        // 권한 필터는 인가 처리 전 인증 검사를 진행해야 한다.
        permitAllFilter.setAuthenticationManager(authenticationManagerBean());
        return permitAllFilter;
    }
```

---

# #08. 계층 권한 적용하기 - RoleHierarchy

- spring은 권한의 상하관계를 알지 못한다.

![image](https://github.com/abc7468/Daou.zip/assets/60870438/c50f56fd-78af-4662-922f-5cda46cf55a8)

- 이를 제공하는 클래스가 RoleHierarchy

### RoleHierarchy

- 상위 계층 Role은 하위 계층 Role의 자원에 접근이 가능하다.
- ROLE_ADMIN > ROLE_MANAGER > ROLE_USER 일 경우 ROLE_ADMIN만 있으면 하위 ROLE의 권한을 모두 포함한다.
- ROLE_ADMIN > ROLE_MANAGER / ROLE_MANAGER > ROLE_USER 의 포맷을 가지고 있다.

### RoleHierarchyVoter

- RoleHierarchy를 생성자로 받으며 voter에서 설정한 규칙이 적용되어 심사한다.

## RoleHierarchy ;entity

```java
@Entity
@Table(name="ROLE_HIERARCHY")
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = {"parentName", "roleHierarchy"})
@Builder
public class RoleHierarchy implements Serializable {

    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "child_name")
    private String childName; // 해당 role

    @ManyToOne(cascade = {CascadeType.ALL},fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_name", referencedColumnName = "child_name")
    private RoleHierarchy parentName; // 부모 role

    @OneToMany(mappedBy = "parentName", cascade={CascadeType.ALL})
    private Set<RoleHierarchy> roleHierarchy = new HashSet<RoleHierarchy>();
}
```

## RoleHierarchyRepository

```java
public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, Long> {

    RoleHierarchy findByChildName(String roleName);
}
```

## RoleHierarchyServiceImpl

```java
@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Transactional
    @Override
    public String findAllHierarchy() {

        List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();
// DB에서 role 가져오기

        Iterator<RoleHierarchy> itr = rolesHierarchy.iterator();
        StringBuffer concatedRoles = new StringBuffer();
        while (itr.hasNext()) {
            RoleHierarchy model = itr.next();
            // 포맷하기
            // ROLE_ADMIN > ROLE_MANAGER /n
            // ROLE_MANAGER > ROLE_USER /n
            if (model.getParentName() != null) {
                concatedRoles.append(model.getParentName().getChildName());
                concatedRoles.append(" > ");
                concatedRoles.append(model.getChildName());
                concatedRoles.append("\n");
            }
        }
        return concatedRoles.toString();
// 최종 문자열 반환
    }
}
```

- 포매팅된 최종

```java
ROLE_ADMIN > ROLE_MANAGER
ROLE_MANAGER > ROLE_USER
```

## SecurityConfig

```java
private AccessDecisionManager affirmativeBased() {
        // 객체 만들 때, voter 여러개 전달 가능. 지금은 하나만
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
        List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
        accessDecisionVoters.add(roleVoter());
        return accessDecisionVoters;
    }

    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
        return null;
    }

    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }
```

- `AccessDecisionVoter` List를 추가한다.
- `RoleHierarchyVoter`와 `RoleHierarchyImple`로 연결해준다.
- `RoleHierarchyImpl`에 우리가 포맷팅한 `RoleHierarchyServiceImpl`을 사용한 결과값을 `setHierarchy`를 사용해 넣어야 한다.
    
- 스프링 부트가 기동될 때 넣어주자.

## SecurityInitalizer

```java
@Component
public class SecurityInitializer implements ApplicationRunner {

    //db로 부터 계층 정보 값을 가져와 포맷팅된 결과값을 hierarchyImpl에 넣어준다.
    @Autowired
    private RoleHierarchyService roleHierarchyService;

    // 포맷팅된 규칙을 갖는 클래스
    @Autowired
    private RoleHierarchyImpl roleHierarchy;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        // 리턴받은 결과값을 저장해주기
        roleHierarchy.setHierarchy(allHierarchy);
    }
}
```

- voter의 생성자로 RoleHierarchyImpl을 넣고 있다.
- voter가 인가처리시 ADMIN이 하위 권한의 모든 것을 가질 수 있게 한다.
