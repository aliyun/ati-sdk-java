package com.aliyun.ati.sdk.model.generated;

import java.net.URI;

/**
 * Represents an endpoint exposed by an ATI-registered agent.
 *
 * <p>Each endpoint has a protocol, an agent URL, and an optional metadata URL.</p>
 */
public class AgentEndpoint {

    private ProtocolEnum protocol;
    private URI agentUrl;
    private URI metaDataUrl;

    /**
     * Supported agent communication protocols.
     */
    public enum ProtocolEnum {
        /** HTTP-based API. */
        HTTP_API("HTTP-API"),
        /** Agent-to-Agent protocol. */
        A2A("A2A"),
        /** Model Context Protocol. */
        MCP("MCP");

        private final String value;

        ProtocolEnum(String value) {
            this.value = value;
        }

        /**
         * Returns the string value of the protocol.
         *
         * @return the protocol value
         */
        public String getValue() {
            return value;
        }
    }

    /**
     * Returns the protocol for this endpoint.
     *
     * @return the protocol
     */
    public ProtocolEnum getProtocol() {
        return protocol;
    }

    /**
     * Sets the protocol for this endpoint.
     *
     * @param protocol the protocol
     */
    public void setProtocol(ProtocolEnum protocol) {
        this.protocol = protocol;
    }

    /**
     * Returns the agent URL.
     *
     * @return the agent URL
     */
    public URI getAgentUrl() {
        return agentUrl;
    }

    /**
     * Sets the agent URL.
     *
     * @param agentUrl the agent URL
     */
    public void setAgentUrl(URI agentUrl) {
        this.agentUrl = agentUrl;
    }

    /**
     * Returns the metadata URL.
     *
     * @return the metadata URL, or null if not available
     */
    public URI getMetaDataUrl() {
        return metaDataUrl;
    }

    /**
     * Sets the metadata URL.
     *
     * @param metaDataUrl the metadata URL
     */
    public void setMetaDataUrl(URI metaDataUrl) {
        this.metaDataUrl = metaDataUrl;
    }
}
