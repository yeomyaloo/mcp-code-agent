package com.codeagent.mcp.findings;

import java.util.List;

/**
 * 취약점 발견. 조사 단계에서 record_finding 으로 OPEN 상태로 만들고, 검증 단계에서 submit_verdict 로 판정한다.
 *
 * @param entryPoint 외부 입력이 들어오는 진입점 (예: GET /api/users/search)
 * @param sink       위험 지점 API (예: org.springframework.jdbc.core.JdbcTemplate.queryForList)
 */
public record Finding(String id, String title, String cwe, String severity, String confidence, String description,
                      String exploitScenario, List<Evidence> evidence, String entryPoint, String sink,
                      Status status, Verification verification, String createdAt) {

    public enum Status {
        /** 검증 대기 */
        OPEN,
        /** 공격 가능함을 확인 */
        CONFIRMED,
        /** 오탐 */
        REJECTED,
        /** 판단 근거 부족 */
        UNCERTAIN
    }

    public record Evidence(String file, int line, String note) {
    }

    /** @param severity 검증 후 다시 매긴 심각도 (없으면 조사 단계 값을 쓴다) */
    public record Verification(String verdict, String reasoning, String blockingControls, String severity,
                               String verifiedAt) {
    }

    /** 검증 후 심각도가 있으면 그것을, 없으면 조사 단계 심각도 */
    public String effectiveSeverity() {
        return verification != null && verification.severity() != null ? verification.severity() : severity;
    }

    Finding withVerdict(Status status, Verification verification) {
        return new Finding(id, title, cwe, severity, confidence, description, exploitScenario, evidence, entryPoint, sink,
                status, verification, createdAt);
    }
}
