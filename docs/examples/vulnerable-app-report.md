# 보안 분석 보고서: vulnerable-app

- 대상: src/test/resources/fixtures/vulnerable-app
- 확정 2 · 검증 대기 0 · 판단 불가 1 · 기각(오탐) 2

| ID | 판정 | 심각도 | CWE | 제목 |
|---|---|---|---|---|
| F1 | 확정 | critical | CWE-89 | 사용자 검색 API의 SQL 인젝션 |
| F2 | 확정 | medium | CWE-78 | ping API의 명령/인자 인젝션 |
| F3 | 판단 불가 | high | CWE-22 | 파일 다운로드 API의 경로 조작 |
| F4 | 기각(오탐) | medium | CWE-78 | CommandService#shell 의 셸 명령 실행 |
| F5 | 기각(오탐) | medium | CWE-502 | FileService#load 의 안전하지 않은 역직렬화와 경로 조작 |

## F1. 사용자 검색 API의 SQL 인젝션

- 판정: **확정** · 심각도: critical · CWE-89 · 조사 확신: high
- 경로: `GET /api/users/search` → `JdbcTemplate.queryForList`

요청 파라미터 name 이 UserController#search → UserServiceImpl#search → findByName 으로 그대로 전달되고, 문자열 연결로 SQL 을 만든 뒤 파라미터 바인딩 없이 queryForList(sql) 로 실행된다.

**공격 예시**

```
GET /api/users/search?name=' OR '1'='1 → users 테이블 전체 조회. name=' UNION SELECT ... -- 로 다른 테이블 유출
```

**근거 코드**

- `src/main/java/com/example/vuln/web/UserController.java:32` @RequestParam name 을 검증 없이 받음
- `src/main/java/com/example/vuln/service/UserServiceImpl.java:24` name 을 작은따옴표 안에 문자열 연결
- `src/main/java/com/example/vuln/service/UserServiceImpl.java:25` 바인딩 없이 SQL 실행

**검증**

UserController.java:32 의 @RequestParam name 이 UserServiceImpl.java:20 → 24 에서 작은따옴표 안에 그대로 연결되고 25 에서 queryForList(sql) 로 바인딩 없이 실행된다. 외부 HTTP 요청으로 바로 닿고, ' 하나로 문자열을 탈출할 수 있어 데이터 유출이 가능하다.

- 확인한 방어 장치: @Valid/@Pattern, 파라미터 바인딩(?), 이스케이프, 보안 필터 모두 없음(grep 결과 없음).

## F2. ping API의 명령/인자 인젝션

- 판정: **확정** · 심각도: medium · CWE-78 · 조사 확신: medium
- 경로: `POST /api/users/ping` → `Runtime.exec`

요청 파라미터 host 가 검증 없이 "ping -c 1 " + host 로 연결되어 Runtime.exec(String) 으로 실행된다. exec(String) 은 셸을 거치지 않고 공백으로 토큰을 나누므로 ;, | 같은 셸 메타문자는 동작하지 않지만, 공백을 넣어 ping 에 임의 옵션·인자를 추가할 수 있다.

**공격 예시**

```
POST /api/users/ping host=-c 1000000 -s 65000 victim.example → 대량 ping 으로 자원 소모·외부 공격 경유. host=-f 10.0.0.1 등 옵션 주입
```

**근거 코드**

- `src/main/java/com/example/vuln/web/UserController.java:37` @RequestParam host 를 검증 없이 받음
- `src/main/java/com/example/vuln/service/CommandService.java:11` 문자열 연결 후 Runtime.exec 실행

**검증**

UserController.java:37 의 host 가 CommandService.java:11 에서 검증 없이 Runtime.exec("ping -c 1 " + host) 로 실행된다. exec(String) 은 StringTokenizer 로 공백 분리만 하고 셸을 거치지 않으므로 ;, |, $() 로 임의 명령을 붙이는 것은 불가능하다. 그러나 공백으로 ping 옵션(-c, -s, -i, -f 등)과 대상을 추가하는 인자 인젝션은 가능해 서버 자원 소모·제3자 대상 트래픽 유발이 된다. 임의 명령 실행이 아니므로 심각도를 medium 으로 낮춘다.

- 확인한 방어 장치: 입력 검증·허용 목록 없음. 셸을 거치지 않는 Runtime.exec(String) 특성이 셸 메타문자 공격만 막음.

## F3. 파일 다운로드 API의 경로 조작

- 판정: **판단 불가** · 심각도: high · CWE-22 · 조사 확신: medium
- 경로: `GET /api/users/files/{name}` → `Files.readAllBytes(Paths.get(BASE_DIR, name))`

경로 변수 name 이 정규화·기준 디렉터리 검사(normalize/startsWith) 없이 Paths.get("/var/data", name) 에 들어가 파일 내용을 그대로 응답한다. ../ 가 들어가면 /var/data 밖 파일을 읽는다.

**공격 예시**

```
GET /api/users/files/..%2F..%2Fetc%2Fpasswd → /etc/passwd 노출 (서버가 인코딩된 슬래시를 허용하는 경우)
```

**근거 코드**

- `src/main/java/com/example/vuln/web/UserController.java:42` @PathVariable name 을 검증 없이 받음
- `src/main/java/com/example/vuln/service/FileService.java:17` 정규화·범위 검사 없이 파일 읽기

**검증**

FileService.java:17 은 normalize/startsWith 검사 없이 Paths.get("/var/data", name) 을 읽으므로 코드 자체는 취약하다. 하지만 UserController.java:41 의 {name} 은 경로 한 구간만 받으므로 ../x 를 넣으려면 인코딩된 슬래시(%2F)나 역슬래시가 필요하고, 이는 내장 Tomcat 의 ALLOW_ENCODED_SLASH, Spring 의 UrlPathHelper/PathPatternParser 설정, 프록시, 운영체제(Windows 의 \ 구분자)에 달려 있다. 이 설정은 저장소에 없다(yml/properties 파일 없음). name=".." 단독은 /var/data/.. 디렉터리라 읽기 실패한다.

- 확인한 방어 장치: 애플리케이션 코드상 방어 없음. 기본 Tomcat/Spring 설정의 인코딩된 슬래시 거부가 막을 수 있으나 저장소 밖 설정에 의존.

## F4. CommandService#shell 의 셸 명령 실행

- 판정: **기각(오탐)** · 심각도: medium · CWE-78 · 조사 확신: low
- 경로: `-` → `ProcessBuilder("sh", "-c", command)`

인자 command 를 sh -c 로 그대로 실행한다. 다만 코드 그래프상 호출하는 쪽이 없어 진입점에서 닿는지 검증 필요.

**근거 코드**

- `src/main/java/com/example/vuln/service/CommandService.java:16` sh -c 로 임의 문자열 실행

**검증**

CommandService.java:15-16 의 shell 은 sh -c 로 임의 명령을 실행하지만, get_callers 결과 호출하는 쪽이 없고 grep 으로 .shell( 호출·리플렉션·@Scheduled 등도 찾지 못했다. 진입점(UserController 의 5개 API)에서 닿지 않아 외부 입력이 들어오지 않는다. 향후 호출이 추가되면 즉시 치명적이 되므로 제거 또는 허용 목록 적용을 권고.

- 확인한 방어 장치: 도달 불가(호출자 없음).

## F5. FileService#load 의 안전하지 않은 역직렬화와 경로 조작

- 판정: **기각(오탐)** · 심각도: medium · CWE-502 · 조사 확신: low
- 경로: `-` → `ObjectInputStream.readObject`

BASE_DIR + "/" + name 경로의 파일을 클래스 필터 없이 ObjectInputStream 으로 역직렬화한다. name 도 검사하지 않는다. 다만 호출하는 쪽이 없어 진입점에서 닿는지 검증 필요.

**근거 코드**

- `src/main/java/com/example/vuln/service/FileService.java:21` 검사 없는 경로로 FileInputStream 생성
- `src/main/java/com/example/vuln/service/FileService.java:22` ObjectInputFilter 없이 readObject

**검증**

FileService.java:20-22 의 load 는 필터 없이 readObject 를 하지만, get_callers 결과 호출하는 쪽이 없고 grep 으로 .load( 호출·리플렉션도 없다. 외부 입력이 닿지 않는다. 또한 공격하려면 /var/data 에 악성 직렬화 파일을 써야 하는데 쓰기 경로도 없다. 사용하지 않는 코드라면 제거하고, 쓸 경우 ObjectInputFilter 를 적용할 것을 권고.

- 확인한 방어 장치: 도달 불가(호출자 없음).
