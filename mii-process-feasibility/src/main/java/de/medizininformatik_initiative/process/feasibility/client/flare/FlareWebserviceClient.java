package de.medizininformatik_initiative.process.feasibility.client.flare;

import java.io.IOException;
import java.net.URI;

/**
 * Describes a client for communicating with a Flare instance.
 */
public interface FlareWebserviceClient {

    /**
     * Given a CCDL query sends this query to a Flare instance in order to request the corresponding feasibility
     * (population count).
     *
     * @param ccdlQuery The query that shall be evaluated.
     * @return Feasibility (population count) corresponding to the evaluated query.
     * @throws IOException If an I/O error occurs when sending or receiving.
     * @throws InterruptedException If the operation is interrupted.
     */
    int requestFeasibility(byte[] ccdlQuery) throws IOException, InterruptedException;

    /**
     * Returns the base url this Flare client is configured to use for sending CCDL queries to.
     *
     * @return configured flare base url
     */
    URI getFlareBaseUrl();

    /**
     * Tests the connection to the flare server using the connection settings configured for this Flare client.
     * <p>
     * Throws an exception if the connection test fails, otherwise the connection test was successful.
     * </p>
     *
     * @throws IOException in case of a problem or the connection was aborted
     */
    void testConnection() throws IOException;
}
