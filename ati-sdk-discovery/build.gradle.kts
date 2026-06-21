dependencies {
    api(project(":ati-sdk-core"))
    implementation("com.aliyun:tea-openapi:0.3.6")
    implementation("com.aliyun:tea-util:0.2.23")
    implementation("com.aliyun:openapiutil:0.2.1")
    implementation("com.fasterxml.jackson.core:jackson-databind:${project.property("jacksonVersion")}")
    implementation("org.slf4j:slf4j-api:${project.property("slf4jVersion")}")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
}
