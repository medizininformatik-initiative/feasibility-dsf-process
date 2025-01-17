package de.medizininformatik_initiative.process.feasibility;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.gclient.IFetchConformanceTyped;
import ca.uhn.fhir.rest.gclient.IFetchConformanceUntyped;
import de.medizininformatik_initiative.process.feasibility.client.flare.FlareWebserviceClient;
import org.hl7.fhir.r4.model.CapabilityStatement;
import org.hl7.fhir.r4.model.CapabilityStatement.CapabilityStatementSoftwareComponent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.FEASIBILITY_EXECUTE_PROCESS_ID;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.FEASIBILITY_REQUEST_PROCESS_ID;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class FeasibilityProcessPluginDeploymentStateListenerTest {

    @Mock FlareWebserviceClient flareClient;
    @Mock IGenericClient storeClient;
    @Mock IFetchConformanceUntyped untypedFetch;
    @Mock IFetchConformanceTyped<CapabilityStatement> typedFetch;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;

    @BeforeEach
    void setup() {
        System.setOut(new PrintStream(out));
        System.setErr(new PrintStream(err));
    }

    @AfterEach
    void restoreStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    @Test
    @DisplayName("connection test is not executed when no process is deployed.")
    void noConnectionTestIfNoProcessDeployed() throws Exception {
        var listener = new FeasibilityProcessPluginDeploymentStateListener(Map.of("foo", storeClient),
                Map.of("bar", flareClient));

        listener.onProcessesDeployed(List.of());

        verify(storeClient, never()).capabilities();
        verify(flareClient, never()).requestFeasibility(any(byte[].class));
    }

    @Test
    @DisplayName("connection test is not executed when 'feasibilityExecute' process is not deployed.")
    void noConnectionTestIfExecuteProcessIsNotDeployed() throws Exception {
        var listener = new FeasibilityProcessPluginDeploymentStateListener(Map.of("foo", storeClient),
                Map.of("bar", flareClient));

        listener.onProcessesDeployed(List.of("foo", FEASIBILITY_REQUEST_PROCESS_ID, "bar"));

        verify(flareClient, never()).requestFeasibility(any(byte[].class));
    }

    @Test
    @DisplayName("flare client connection test succeeds when evaluation strategy is 'structured-query' and no error occurs")
    void flareClientConnectionTestSucceeds() throws Exception {
        var storeId = "foo";
        var listener = new FeasibilityProcessPluginDeploymentStateListener(Map.of(), Map.of(storeId, flareClient));

        listener.onProcessesDeployed(List.of(FEASIBILITY_EXECUTE_PROCESS_ID));

        verify(flareClient).testConnection();
        assertThat(out.toString(),
                containsString("Feasibility plugin connection test to FHIR store '%s' (Flare) SUCCEEDED."
                        .formatted(storeId)));
    }

    @Test
    @DisplayName("store client connection test succeeds when evaluation strategy is 'cql' and no error occurs")
    void storeClientConnectionTestSucceeds() throws Exception {
        var softwareName = "software-213030";
        var softwareVersion = "version-213136";
        var software = new CapabilityStatementSoftwareComponent()
                .setName(softwareName)
                .setVersion(softwareVersion);
        var statement = new CapabilityStatement().setSoftware(software);
        var storeId = "foo";
        when(storeClient.capabilities()).thenReturn(untypedFetch);
        when(untypedFetch.ofType(CapabilityStatement.class)).thenReturn(typedFetch);
        when(typedFetch.execute()).thenReturn(statement);
        var listener = new FeasibilityProcessPluginDeploymentStateListener(Map.of(storeId, storeClient), Map.of());

        listener.onProcessesDeployed(List.of(FEASIBILITY_EXECUTE_PROCESS_ID));
        assertThat(out.toString(),
                containsString("Feasibility plugin connection test to FHIR store '%s' (%s - %s) SUCCEEDED."
                        .formatted(storeId, softwareName, softwareVersion)));
    }

    @Test
    @DisplayName("flare client connection test fails when evaluation strategy is 'structured-query' and error occurs")
    void flareClientConnectionTestFails() throws Exception {
        var errorMessage = "error-223236";
        var exception = new IOException(errorMessage);
        doThrow(exception).when(flareClient).testConnection();
        String storeId = "foo";
        var listener = new FeasibilityProcessPluginDeploymentStateListener(Map.of(), Map.of(storeId, flareClient));

        listener.onProcessesDeployed(List.of(FEASIBILITY_EXECUTE_PROCESS_ID));

        assertThat(out.toString(),
                containsString(format("Feasibility plugin connection test to FHIR store '%s' FAILED. Error: %s - %s",
                        storeId, exception.getClass().getName(), errorMessage)));
    }

    @Test
    @DisplayName("store client connection test fails when evaluation strategy is 'cql' and error occurs")
    void storeClientConnectionTestFails() throws Exception {
        var errorMessage = "error-223622";
        var exception = new RuntimeException(errorMessage);
        var storeId = "foo";
        when(storeClient.capabilities()).thenReturn(untypedFetch);
        when(untypedFetch.ofType(CapabilityStatement.class)).thenReturn(typedFetch);
        doThrow(exception).when(typedFetch).execute();

        var listener = new FeasibilityProcessPluginDeploymentStateListener(Map.of(storeId, storeClient), Map.of());

        listener.onProcessesDeployed(List.of(FEASIBILITY_EXECUTE_PROCESS_ID));
        assertThat(out.toString(),
                containsString(format("Feasibility plugin connection test to FHIR store '%s' FAILED. Error: %s - %s",
                        storeId, exception.getClass().getName(), errorMessage)));

    }
}
