package de.medizininformatik_initiative.process.feasibility.spring.config;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import de.medizininformatik_initiative.process.feasibility.EnhancedFhirWebserviceClientProvider;
import de.medizininformatik_initiative.process.feasibility.EnhancedFhirWebserviceClientProviderImpl;
import de.medizininformatik_initiative.process.feasibility.FeasibilityCachingLaplaceCountObfuscator;
import de.medizininformatik_initiative.process.feasibility.FeasibilityProcessPluginDeploymentStateListener;
import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings;
import de.medizininformatik_initiative.process.feasibility.Obfuscator;
import de.medizininformatik_initiative.process.feasibility.RateLimit;
import de.medizininformatik_initiative.process.feasibility.client.flare.FlareWebserviceClient;
import de.medizininformatik_initiative.process.feasibility.client.listener.SetCorrelationKeyListener;
import de.medizininformatik_initiative.process.feasibility.message.SendDicRequest;
import de.medizininformatik_initiative.process.feasibility.message.SendDicResponse;
import de.medizininformatik_initiative.process.feasibility.service.DownloadFeasibilityResources;
import de.medizininformatik_initiative.process.feasibility.service.DownloadMeasureReport;
import de.medizininformatik_initiative.process.feasibility.service.EvaluateCQLMeasure;
import de.medizininformatik_initiative.process.feasibility.service.EvaluateRequestRate;
import de.medizininformatik_initiative.process.feasibility.service.EvaluateCCDLMeasure;
import de.medizininformatik_initiative.process.feasibility.service.FeasibilityResourceCleaner;
import de.medizininformatik_initiative.process.feasibility.service.LogReceiveTimeout;
import de.medizininformatik_initiative.process.feasibility.service.MergeMeasureResults;
import de.medizininformatik_initiative.process.feasibility.service.ObfuscateEvaluationResult;
import de.medizininformatik_initiative.process.feasibility.service.RateLimitExceededTaskRejecter;
import de.medizininformatik_initiative.process.feasibility.service.SelectRequestTargets;
import de.medizininformatik_initiative.process.feasibility.service.SelectResponseTarget;
import de.medizininformatik_initiative.process.feasibility.service.SetupEvaluationSettings;
import de.medizininformatik_initiative.process.feasibility.service.StoreFeasibilityResources;
import de.medizininformatik_initiative.process.feasibility.service.StoreLiveResult;
import de.medizininformatik_initiative.process.feasibility.service.StoreMeasureReport;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.service.FhirWebserviceClientProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.DEFAULT_OBFUSCATION_LAPLACE_EPSILON;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.DEFAULT_OBFUSCATION_LAPLACE_SENSITIVITY;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.DEFAULT_RATE_LIMIT_COUNT;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.DEFAULT_RATE_LIMIT_DURATION;

@Configuration
public class FeasibilityConfig {

    @Autowired private ProcessPluginApi api;

    public FeasibilityConfig() {
    }

    @Bean
    public EnhancedFhirWebserviceClientProvider enhancedFhirClientProvider(@Qualifier("clientProvider") FhirWebserviceClientProvider fhirClientProvider) {
        return new EnhancedFhirWebserviceClientProviderImpl(fhirClientProvider);
    }

    @Bean
    public Obfuscator<Integer> feasibilityCountObfuscator() {
        return new FeasibilityCachingLaplaceCountObfuscator(DEFAULT_OBFUSCATION_LAPLACE_SENSITIVITY,
                DEFAULT_OBFUSCATION_LAPLACE_EPSILON);
    }

    //
    // process requestFeasibility implementations
    //

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public SelectRequestTargets selectRequestTargets() {
        return new SelectRequestTargets(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public SendDicRequest sendDicRequests() {
        return new SendDicRequest(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public DownloadMeasureReport downloadMeasureReport(EnhancedFhirWebserviceClientProvider enhancedFhirClientProvider) {
        return new DownloadMeasureReport(enhancedFhirClientProvider, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public StoreLiveResult storeLiveResult() {
        return new StoreLiveResult(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public LogReceiveTimeout logReceiveTimeout() {
        return new LogReceiveTimeout(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public SetCorrelationKeyListener setCorrelationKeyListener() {
        return new SetCorrelationKeyListener(api);
    }

    //
    // process executeFeasibility implementations
    //

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public EvaluateRequestRate requestRateLimiters(FeasibilitySettings feasibilitySettings) {
        return new EvaluateRequestRate(api,
                feasibilitySettings.networks().entrySet().stream()
                        .collect(Collectors.toMap(e -> e.getKey(),
                                e -> Optional.ofNullable(e.getValue().rateLimit())
                                        .map(r -> new RateLimit(r.count(), r.interval()))
                                        .orElse(new RateLimit(DEFAULT_RATE_LIMIT_COUNT,
                                                DEFAULT_RATE_LIMIT_DURATION)))));
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public RateLimitExceededTaskRejecter rateLimitExceededTaskRejecter() {
        return new RateLimitExceededTaskRejecter(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public SetupEvaluationSettings setupEvaluationSettings(FeasibilitySettings feasibilitySettings) {
        return new SetupEvaluationSettings(feasibilitySettings, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public DownloadFeasibilityResources downloadFeasibilityResources(
            EnhancedFhirWebserviceClientProvider enhancedFhirClientProvider) {
        return new DownloadFeasibilityResources(enhancedFhirClientProvider, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public StoreFeasibilityResources storeFeasibilityResources(Map<String, Set<String>> networkStores,
                                                               Map<String, IGenericClient> storeClients) {
        return new StoreFeasibilityResources(networkStores, storeClients, api, new FeasibilityResourceCleaner());
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public EvaluateCQLMeasure evaluateCqlMeasure(Map<String, Set<String>> networkStores,
                                                 Map<String, IGenericClient> storeClients) {
        return new EvaluateCQLMeasure(networkStores, storeClients, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public EvaluateCCDLMeasure evaluateStructureQueryMeasure(Map<String, Set<String>> networkStores,
                                                                        Map<String, FlareWebserviceClient> flareClients) {
        return new EvaluateCCDLMeasure(networkStores, flareClients, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public ObfuscateEvaluationResult obfuscateEvaluationResult(Obfuscator<Integer> feasibilityCountObfuscator) {
        return new ObfuscateEvaluationResult(feasibilityCountObfuscator, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public StoreMeasureReport storeMeasureReport() {
        return new StoreMeasureReport(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public SelectResponseTarget selectResponseTarget() {
        return new SelectResponseTarget(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public SendDicResponse sendDicResponse() {
        return new SendDicResponse(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public MergeMeasureResults mergeMeasureResults() {
        return new MergeMeasureResults(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public FeasibilityProcessPluginDeploymentStateListener deploymentStateListener(Map<String, IGenericClient> storeClients,
                                                                                   Map<String, FlareWebserviceClient> flareClients) {
        return new FeasibilityProcessPluginDeploymentStateListener(storeClients, flareClients);
    }
}
