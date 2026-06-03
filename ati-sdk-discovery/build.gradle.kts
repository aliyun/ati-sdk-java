val dnsjavaVersion: String by project

dependencies {
    api(project(":ati-sdk-core"))
    implementation("dnsjava:dnsjava:$dnsjavaVersion")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.mockito:mockito-core:${project.property("mockitoVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
    testRuntimeOnly("org.slf4j:slf4j-simple:${project.property("slf4jVersion")}")
}
