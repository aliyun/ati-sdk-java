dependencies {
    api(project(":ati-sdk-core"))
    api(project(":ati-sdk-discovery"))
    api(project(":ati-sdk-transparency"))
    implementation("dnsjava:dnsjava:${project.property("dnsjavaVersion")}")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.mockito:mockito-core:${project.property("mockitoVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
    testRuntimeOnly("org.slf4j:slf4j-simple:${project.property("slf4jVersion")}")
}
