val springBootVersion: String by project

dependencies {
    api(project(":ati-sdk-agent-client"))
    api(project(":ati-sdk-discovery"))
    implementation("org.springframework.boot:spring-boot-autoconfigure:$springBootVersion")
    compileOnly("org.springframework.boot:spring-boot:$springBootVersion")
    compileOnly("org.springframework.boot:spring-boot-starter-web:$springBootVersion")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor:$springBootVersion")

    testImplementation("org.springframework.boot:spring-boot-starter-test:$springBootVersion")
    testImplementation("org.springframework.boot:spring-boot-starter-web:$springBootVersion")
    testImplementation(testFixtures(project(":ati-sdk-agent-client")))
    testImplementation("org.wiremock:wiremock:${project.property("wiremockVersion")}")
    testImplementation("org.bouncycastle:bcprov-jdk18on:${project.property("bouncyCastleVersion")}")
    testImplementation("org.bouncycastle:bcpkix-jdk18on:${project.property("bouncyCastleVersion")}")
    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
}
