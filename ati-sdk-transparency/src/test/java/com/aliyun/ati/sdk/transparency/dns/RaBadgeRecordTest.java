package com.aliyun.ati.sdk.transparency.dns;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RaBadgeRecordTest {

    private static final String AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String BADGE_URL =
        "https://ati-tl.cnnic.cn:8180/tl/agents/" + AGENT_ID;

    @Test
    @DisplayName("Should parse Badge TXT when keys are reordered")
    void shouldParseReorderedAvAndUKeys() {
        String txtValue = "u=" + BADGE_URL + "; av=v1.0.0; v=ati-badge1";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ati-badge1");
        assertThat(record.agentVersion()).isEqualTo("v1.0.0");
        assertThat(record.url()).isEqualTo(BADGE_URL);
        assertThat(record.agentId()).isEqualTo(AGENT_ID);
        assertThat(record.tlPath()).isEqualTo("/tl/agents/" + AGENT_ID);
        assertThat(record.isSupportedBadgeFormat()).isTrue();
    }

    @Test
    @DisplayName("Should skip records that only have obsolete version=/url= keys")
    void shouldSkipObsoleteVersionAndUrlKeys() {
        assertThat(RaBadgeRecord.parse(
            "v=ati-badge1; version=1.0.0; url=" + BADGE_URL)).isNull();
        assertThat(RaBadgeRecord.parse(
            "v=ati-badge1; av=1.0.0; url=" + BADGE_URL)).isNull();
    }

    @Test
    @DisplayName("Should ignore url= when canonical u= is present")
    void shouldUseCanonicalUWhenUrlAlsoPresent() {
        String txtValue = "v=ati-badge1; av=1.0.0; url=https://legacy.example/old; u=" + BADGE_URL;

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.url()).isEqualTo(BADGE_URL);
    }

    @Test
    @DisplayName("Should skip unimplemented and out-of-family Badge format versions")
    void shouldSkipNonAtiBadge1FormatVersions() {
        assertThat(RaBadgeRecord.parse(
            "v=ati-badge2; av=1.0.0; u=" + BADGE_URL)).isNull();
        assertThat(RaBadgeRecord.parse(
            "v=ra-badge1; av=1.0.0; u=" + BADGE_URL)).isNull();
        assertThat(RaBadgeRecord.parse(
            "v=ATI-BADGE1; av=1.0.0; u=" + BADGE_URL)).isNull();
        assertThat(RaBadgeRecord.parse(
            "v=ati-badge; av=1.0.0; u=" + BADGE_URL)).isNull();
    }

    @Test
    @DisplayName("Should skip records missing av")
    void shouldSkipMissingAv() {
        assertThat(RaBadgeRecord.parse("v=ati-badge1; u=" + BADGE_URL)).isNull();
    }

    @Test
    @DisplayName("Should accept v/V-prefixed and bare SemVer av")
    void shouldAcceptPrefixedAndBareSemVerAv() {
        assertThat(RaBadgeRecord.parse("v=ati-badge1; av=v1.0.0; u=" + BADGE_URL).agentVersion())
            .isEqualTo("v1.0.0");
        assertThat(RaBadgeRecord.parse("v=ati-badge1; av=V1.0.0; u=" + BADGE_URL).agentVersion())
            .isEqualTo("V1.0.0");
        assertThat(RaBadgeRecord.parse("v=ati-badge1; av=1.0.0; u=" + BADGE_URL).agentVersion())
            .isEqualTo("1.0.0");
    }

    @Test
    @DisplayName("Should skip blank or non-SemVer av")
    void shouldSkipBlankOrNonSemVerAv() {
        assertThat(RaBadgeRecord.parse("v=ati-badge1; av=; u=" + BADGE_URL)).isNull();
        assertThat(RaBadgeRecord.parse("v=ati-badge1; av=foo; u=" + BADGE_URL)).isNull();
    }

    @Test
    @DisplayName("Should skip blank u and parse non-blank u without host or scheme checks")
    void shouldParseNonBlankUWithoutHostOrSchemeChecks() {
        assertThat(RaBadgeRecord.parse("v=ati-badge1; av=1.0.0; u=")).isNull();

        RaBadgeRecord httpRecord = RaBadgeRecord.parse(
            "v=ati-badge1; av=1.0.0; u=http://example.com/tl/agents/" + AGENT_ID);
        assertThat(httpRecord).isNotNull();
        assertThat(httpRecord.url()).isEqualTo("http://example.com/tl/agents/" + AGENT_ID);

        RaBadgeRecord untrustedHost = RaBadgeRecord.parse(
            "v=ati-badge1; av=1.0.0; u=https://evil.example/tl/agents/" + AGENT_ID);
        assertThat(untrustedHost).isNotNull();
        assertThat(untrustedHost.url()).isEqualTo("https://evil.example/tl/agents/" + AGENT_ID);
    }

    @Test
    @DisplayName("Should ignore stray m= as an unknown Badge key")
    void shouldIgnoreStrayMOnBadgeTxt() {
        String txtValue = "v=ati-badge1; av=1.0.0; u=" + BADGE_URL + "; m=card";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.url()).isEqualTo(BADGE_URL);
        assertThat(record.agentVersion()).isEqualTo("1.0.0");
    }

    @Test
    @DisplayName("Should last-win duplicate u= and ignore surrounding whitespace")
    void shouldLastWinDuplicateUAndIgnoreWhitespace() {
        String txtValue = "  v = ati-badge1 ; av = 1.0.0 ; u = https://first.example/a ; "
            + "u = " + BADGE_URL + "  ";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ati-badge1");
        assertThat(record.url()).isEqualTo(BADGE_URL);
    }

    @Test
    @DisplayName("Should not treat uppercase V/AV/U as required fields")
    void shouldSkipUppercaseRequiredKeys() {
        assertThat(RaBadgeRecord.parse(
            "V=ati-badge1; AV=1.0.0; U=" + BADGE_URL)).isNull();
    }

    @Test
    @DisplayName("Should return null for null, blank, or unparseable input")
    void shouldReturnNullForNullBlankOrInvalidInput() {
        assertThat(RaBadgeRecord.parse(null)).isNull();
        assertThat(RaBadgeRecord.parse("")).isNull();
        assertThat(RaBadgeRecord.parse("   ")).isNull();
        assertThat(RaBadgeRecord.parse("not a valid _ati-badge record")).isNull();
        assertThat(RaBadgeRecord.parse("v=ati-badge1")).isNull();
    }

    @Test
    @DisplayName("Should extract agentId and tlPath from CNNIC TL URL")
    void shouldExtractFromCnnicTlUrl() {
        String txtValue = "v=ati-badge1; av=1.0.4; "
            + "u=https://tl.atiagent.cn:8180/tl/agents/effae2b2-f451-4c1c-addd-212c649ef5bd/logs/latest";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.agentId()).isEqualTo("effae2b2-f451-4c1c-addd-212c649ef5bd");
        assertThat(record.tlPath())
            .isEqualTo("/tl/agents/effae2b2-f451-4c1c-addd-212c649ef5bd/logs/latest");
        assertThat(record.agentVersion()).isEqualTo("1.0.4");
    }

    @Test
    @DisplayName("Should extract tlPath with trailing slash")
    void shouldExtractTlPathWithTrailingSlash() {
        String txtValue = "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/abc-123/";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.agentId()).isEqualTo("abc-123");
        assertThat(record.tlPath()).isEqualTo("/tl/agents/abc-123/");
    }

    @Test
    @DisplayName("Should implement equals, hashCode, and toString")
    void shouldImplementEqualsHashCodeAndToString() {
        String txtValue = "v=ati-badge1; av=1.0.0; u=https://example.com/v1/agents/test-id";

        RaBadgeRecord record1 = RaBadgeRecord.parse(txtValue);
        RaBadgeRecord record2 = RaBadgeRecord.parse(txtValue);

        assertThat(record1).isEqualTo(record2);
        assertThat(record1.hashCode()).isEqualTo(record2.hashCode());
        assertThat(record1.toString())
            .contains("badgeVersion='ati-badge1'")
            .contains("agentVersion='1.0.0'")
            .contains("test-id");
    }
}
