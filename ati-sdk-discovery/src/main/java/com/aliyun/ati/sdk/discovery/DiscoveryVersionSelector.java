package com.aliyun.ati.sdk.discovery;

import org.semver4j.RangesList;
import org.semver4j.RangesListFactory;
import org.semver4j.Semver;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Selects agent versions from Discovery TXT records using SemVer constraints.
 */
final class DiscoveryVersionSelector {

    private DiscoveryVersionSelector() {
    }

    /**
     * Returns the latest {@code av} among records matching the optional constraint.
     *
     * @param records parsed discovery TXT records
     * @param versionConstraint optional SemVer constraint (e.g. {@code ^1.0.0})
     * @return normalized version string without {@code v} prefix
     */
    static String selectLatestVersion(List<AtiDiscoveryRecord> records, String versionConstraint) {
        Objects.requireNonNull(records, "records must not be null");
        if (records.isEmpty()) {
            throw new IllegalArgumentException("records must not be empty");
        }

        if (versionConstraint == null || versionConstraint.isBlank()) {
            return records.stream()
                .map(AtiDiscoveryRecord::getAgentVersion)
                .map(DiscoveryVersionSelector::parseVersion)
                .max(Comparator.naturalOrder())
                .map(Semver::getVersion)
                .orElseThrow();
        }

        RangesList range = RangesListFactory.create(versionConstraint.trim());
        Optional<Semver> latest = records.stream()
            .map(AtiDiscoveryRecord::getAgentVersion)
            .map(DiscoveryVersionSelector::parseVersion)
            .filter(range::isSatisfiedBy)
            .max(Comparator.naturalOrder());

        return latest.orElseThrow(() -> new IllegalArgumentException(
            "No discovery TXT record matches version constraint: " + versionConstraint))
            .getVersion();
    }

    static boolean versionsEqual(String avFromTxt, String selectedVersion) {
        return parseVersion(avFromTxt).isEquivalentTo(parseVersion(selectedVersion));
    }

    static Semver parseVersion(String av) {
        String normalized = av.startsWith("v") || av.startsWith("V") ? av.substring(1) : av;
        Semver parsed = Semver.parse(normalized);
        if (parsed == null) {
            throw new IllegalArgumentException("Invalid agent version: " + av);
        }
        return parsed;
    }
}
