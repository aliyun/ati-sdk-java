dependencies {
    api(project(":ati-sdk-core"))
    api(project(":ati-sdk-transparency"))
    implementation("dnsjava:dnsjava:${project.property("dnsjavaVersion")}")
    implementation("com.github.ben-manes.caffeine:caffeine:${project.property("caffeineVersion")}")
    implementation("com.fasterxml.jackson.core:jackson-databind:${project.property("jacksonVersion")}")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:${project.property("jacksonVersion")}")
    implementation("org.bouncycastle:bcprov-jdk18on:${project.property("bouncyCastleVersion")}")
    implementation("org.bouncycastle:bcpkix-jdk18on:${project.property("bouncyCastleVersion")}")
    implementation("org.slf4j:slf4j-api:${project.property("slf4jVersion")}")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.mockito:mockito-core:${project.property("mockitoVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
    testImplementation("io.github.erdtman:java-json-canonicalization:1.1")
    testRuntimeOnly("org.slf4j:slf4j-simple:${project.property("slf4jVersion")}")
}
