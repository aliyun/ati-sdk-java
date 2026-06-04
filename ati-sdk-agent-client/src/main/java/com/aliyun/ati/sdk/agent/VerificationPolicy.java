package com.aliyun.ati.sdk.agent;

import java.util.Objects;

public final class VerificationPolicy {

    public static final VerificationPolicy BRONZE =
        new VerificationPolicy("BRONZE",
            VerificationMode.DISABLED, VerificationMode.DISABLED);
    public static final VerificationPolicy SILVER =
        new VerificationPolicy("SILVER",
            VerificationMode.REQUIRED, VerificationMode.DISABLED);
    public static final VerificationPolicy GOLD =
        new VerificationPolicy("GOLD",
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
