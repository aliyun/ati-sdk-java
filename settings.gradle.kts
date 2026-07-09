rootProject.name = "ati-java-sdk"

include("ati-sdk-core")
include("ati-sdk-discovery")
include("ati-sdk-transparency")
include("ati-sdk-agent-client")
include("ati-sdk-spring-boot-starter")

// Examples - not published to Maven, but useful for users of the SDK to reference and run locally
include("ati-sdk-agent-client:examples:http-api")
include("ati-sdk-agent-client:examples:mcp-client")
