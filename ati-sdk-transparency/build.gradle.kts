val bouncyCastleVersion: String by project
val caffeineVersion: String by project

dependencies {
    api(project(":ati-sdk-core"))
    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")
    implementation("com.github.ben-manes.caffeine:caffeine:$caffeineVersion")
    implementation("com.fasterxml.jackson.core:jackson-databind:${project.property("jacksonVersion")}")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:${project.property("jacksonVersion")}")
    implementation("io.github.erdtman:java-json-canonicalization:1.1")
    implementation("com.upokecenter:cbor:4.5.4")
    implementation("dnsjava:dnsjava:${project.property("dnsjavaVersion")}")
    implementation("org.semver4j:semver4j:5.3.0")
    implementation("org.slf4j:slf4j-api:${project.property("slf4jVersion")}")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.mockito:mockito-core:${project.property("mockitoVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
    testImplementation("org.wiremock:wiremock:${project.property("wiremockVersion")}")
    testRuntimeOnly("org.slf4j:slf4j-simple:${project.property("slf4jVersion")}")
}
