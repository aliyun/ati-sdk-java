val jacksonVersion: String by project
val slf4jVersion: String by project
val junitVersion: String by project
val mockitoVersion: String by project
val assertjVersion: String by project

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")

    implementation("org.slf4j:slf4j-api:$slf4jVersion")

    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.mockito:mockito-core:$mockitoVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")
    testRuntimeOnly("org.slf4j:slf4j-simple:$slf4jVersion")
}
