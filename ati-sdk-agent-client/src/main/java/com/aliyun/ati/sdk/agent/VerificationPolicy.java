package com.aliyun.ati.sdk.agent;

import java.util.Objects;

public final class VerificationPolicy {

    public static final VerificationPolicy PKI_ONLY =
        new VerificationPolicy("PKI_ONLY",
            VerificationMode.DISABLED, VerificationMode.DISABLED);
    public static final VerificationPolicy BADGE_REQUIRED =
        new VerificationPolicy("BADGE_REQUIRED",
            VerificationMode.DISABLED, VerificationMode.REQUIRED);
    public static final VerificationPolicy DANE_REQUIRED =
        new VerificationPolicy("DANE_REQUIRED",
            VerificationMode.REQUIRED, VerificationMode.DISABLED);
    public static final VerificationPolicy DANE_AND_BADGE =
        new VerificationPolicy("DANE_AND_BADGE",
            VerificationMode.REQUIRED, VerificationMode.REQUIRED);

    private final String name;
    private final VerificationMode daneMode;
    private final VerificationMode badgeMode;

    public VerificationPolicy(String name,
                              VerificationMode daneMode,
                              VerificationMode badgeMode) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.daneMode = Objects.requireNonNull(daneMode,
            "daneMode must not be null");
        this.badgeMode = Objects.requireNonNull(badgeMode,
            "badgeMode must not be null");
    }

    public String getName() {
        return name;
    }

    public VerificationMode getDaneMode() {
        return daneMode;
    }

    public VerificationMode getBadgeMode() {
        return badgeMode;
    }

    @Override
    public String toString() {
        return name;
    }
}
