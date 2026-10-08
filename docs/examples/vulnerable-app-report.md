# 보안 분석 보고서: vulnerable-app

- 대상: src/test/resources/fixtures/vulnerable-app
- 확정 1 · 검증 대기 0 · 판단 불가 0 · 기각(오탐) 0

| ID | 판정 | 심각도 | CWE | 제목 |
|---|---|---|---|---|
| F1 | 확정 | high | CWE-89 | 사용자 검색 API의 SQL 인젝션 |

## F1. 사용자 검색 API의 SQL 인젝션

- 판정: **확정** · 심각도: high · CWE-89 · 조사 확신: high
- 경로: `GET /api/users/search` → `JdbcTemplate.queryForList`

쿼리 파라미터 name 이 @RequestParam 으로 들어와(UserController.java:32) 검증 없이 UserService.search → UserServiceImpl.search → findByName 으로 전달되고, UserServiceImpl.java:24 에서 작은따옴표 안에 문자열로 이어 붙여 SQL 을 만든 뒤 :25 에서 jdbcTemplate.queryForList(sql) 로 실행된다. 바인드 파라미터를 쓰지 않으며, 저장소에서 @Valid/@Pattern, 필터, 인터셉터, 이스케이프 처리를 찾지 못했다.

**공격 예시**

```
GET /api/users/search?name=x'%20OR%20'1'='1 → 실행되는 SQL: select * from users where name = 'x' OR '1'='1' → users 테이블의 모든 행이 반환됨. UNION SELECT 를 쓰면 다른 테이블 데이터도 빼낼 수 있다.
```

**근거 코드**

- `src/main/java/com/example/vuln/web/UserController.java:32` 외부 입력 name 을 @RequestParam 으로 받아 검증 없이 서비스로 전달
- `src/main/java/com/example/vuln/service/UserServiceImpl.java:24` name 을 SQL 문자열 리터럴 안에 그대로 이어 붙임
- `src/main/java/com/example/vuln/service/UserServiceImpl.java:25` 이어 붙여 만든 SQL 을 파라미터 바인딩 없이 queryForList 로 실행

**검증**

코드를 다시 읽었다. UserController.java:31-33 의 GET /api/users/search 가 @RequestParam name 을 그대로 userService.search 로 넘긴다. UserService 의 구현체는 UserServiceImpl(UserServiceImpl.java:10) 하나뿐이고 @Primary/@Profile 로 바뀌는 다른 빈도 없다. 그래서 호출은 search(:19) → findByName(:20, :23) 으로 이어지고, findByName 을 부르는 곳도 search 하나뿐이다(get_callers). :24 에서 name 을 '...' 리터럴 안에 그대로 이어 붙이고, :25 에서 queryForList(sql) 로 바인드 인자 없이 실행한다. 그러므로 name=x' OR '1'='1 같은 값이 그대로 SQL 구문이 된다.

- 확인한 방어 장치: 찾아본 방어 장치: @Valid/@Validated/@Pattern 입력 검증, Spring Security SecurityFilterChain, 서블릿 Filter·Interceptor, @ControllerAdvice, AOP(@Aspect/@Around), escape/sanitize 처리, 설정 파일(yml/properties/xml). 저장소에서 하나도 찾지 못했다. Spring 이 @RequestParam 문자열을 변환할 때 작은따옴표를 이스케이프하지 않으므로 공격을 막는 장치가 없다.
