dependencies {
    api(project(":ati-sdk-core"))
    implementation("dnsjava:dnsjava:${project.property("dnsjavaVersion")}")
    implementation("org.semver4j:semver4j:5.3.0")
    implementation("org.slf4j:slf4j-api:${project.property("slf4jVersion")}")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
}
