package de.medizininformatik_initiative.process.feasibility;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import de.medizininformatik_initiative.process.feasibility.client.flare.FlareWebserviceClient;
import dev.dsf.bpe.v1.ProcessPluginDeploymentStateListener;
import org.hl7.fhir.r4.model.CapabilityStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.List;
import java.util.Map;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.FEASIBILITY_EXECUTE_PROCESS_ID;
import static java.util.Objects.requireNonNull;

/**
 * After process deployment starts a connection test if the <i>feasibilityExecute</i> process is active.
 * <p>
 * The configured {@link EvaluationStrategy} determines which client is used for the connection test.
 * </p>
 *
 * @author <a href="mailto:math2306@hotmail.com">Mathias Rühle</a>
 */
public class FeasibilityProcessPluginDeploymentStateListener
        implements ProcessPluginDeploymentStateListener, InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(FeasibilityProcessPluginDeploymentStateListener.class);

    private Map<String, IGenericClient> storeClients;
    private Map<String, FlareWebserviceClient> flareWebserviceClients;

    public FeasibilityProcessPluginDeploymentStateListener(Map<String, IGenericClient> storeClients,
            Map<String, FlareWebserviceClient> flareWebserviceClients) {
        this.storeClients = storeClients;
        this.flareWebserviceClients = flareWebserviceClients;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        requireNonNull(storeClients);
        requireNonNull(flareWebserviceClients);
    }

    @Override
    public void onProcessesDeployed(List<String> processes) {
        if (processes.contains(FEASIBILITY_EXECUTE_PROCESS_ID)) {
            if (storeClients.size() > 0 || flareWebserviceClients.size() > 0) {
                storeClients.entrySet().parallelStream().forEach(s -> {
                    try {
                        var statement = s.getValue().capabilities().ofType(CapabilityStatement.class).execute();
                        var software = statement.getSoftware();
                        logger.info("Feasibility plugin connection test to FHIR store '{}' ({} - {}) SUCCEEDED.",
                                s.getKey(), software.getName(), software.getVersion());
                    } catch (Exception e) {
                        logger.error("Feasibility plugin connection test to FHIR store '{}' FAILED. Error: {} - {}",
                                s.getKey(), e.getClass().getName(), e.getMessage());
                    }
                });

                flareWebserviceClients.entrySet().parallelStream().forEach(f -> {
                    try {
                        f.getValue().testConnection();
                        logger.info("Feasibility plugin connection test to FHIR store '{}' (Flare) SUCCEEDED.",
                                f.getKey());
                    } catch (Exception e) {
                        logger.error("Feasibility plugin connection test to FHIR store '{}' FAILED. Error: {} - {}",
                                f.getKey(), e.getClass().getName(), e.getMessage());
                    }
                });
            } else {
                logger.warn("Feasibility Execute process activated, but no stores configured"
                                + " in configuration file for executing feasibility queries.");
            }
        }
    }
}
