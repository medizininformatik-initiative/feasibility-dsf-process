package de.medizininformatik_initiative.process.feasibility.spring.config;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import de.medizininformatik_initiative.process.feasibility.EnhancedFhirWebserviceClientProvider;
import de.medizininformatik_initiative.process.feasibility.EnhancedFhirWebserviceClientProviderImpl;
import de.medizininformatik_initiative.process.feasibility.EvaluationSettingsProvider;
import de.medizininformatik_initiative.process.feasibility.FeasibilityCachingLaplaceCountObfuscator;
import de.medizininformatik_initiative.process.feasibility.FeasibilityProcessPluginDeploymentStateListener;
import de.medizininformatik_initiative.process.feasibility.Obfuscator;
import de.medizininformatik_initiative.process.feasibility.RateLimit;
import de.medizininformatik_initiative.process.feasibility.client.flare.FlareWebserviceClient;
import de.medizininformatik_initiative.process.feasibility.client.listener.SetCorrelationKeyListener;
import de.medizininformatik_initiative.process.feasibility.message.SendDicRequest;
import de.medizininformatik_initiative.process.feasibility.message.SendDicResponse;
import de.medizininformatik_initiative.process.feasibility.service.DownloadFeasibilityResources;
import de.medizininformatik_initiative.process.feasibility.service.DownloadMeasureReport;
import de.medizininformatik_initiative.process.feasibility.service.EvaluateCqlMeasure;
import de.medizininformatik_initiative.process.feasibility.service.EvaluateRequestRate;
import de.medizininformatik_initiative.process.feasibility.service.EvaluateStructuredQueryMeasure;
import de.medizininformatik_initiative.process.feasibility.service.FeasibilityResourceCleaner;
import de.medizininformatik_initiative.process.feasibility.service.LogReceiveTimeout;
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

@Configuration
public class FeasibilityConfig {

    private final IGenericClient storeClient;

    @Autowired private ProcessPluginApi api;

    private final EvaluationSettingsProvider evaluationSettingsProvider;
    private final FlareWebserviceClient flareWebserviceClient;

    public FeasibilityConfig(@Qualifier("store-client") IGenericClient storeClient,
                             EvaluationSettingsProvider evaluationSettingsProvider,
                             FlareWebserviceClient flareWebserviceClient) {
        this.storeClient = storeClient;
        this.evaluationSettingsProvider = evaluationSettingsProvider;
        this.flareWebserviceClient = flareWebserviceClient;
    }

    @Bean
    public EnhancedFhirWebserviceClientProvider enhancedFhirClientProvider(@Qualifier("clientProvider") FhirWebserviceClientProvider fhirClientProvider) {
        return new EnhancedFhirWebserviceClientProviderImpl(fhirClientProvider);
    }

    @Bean
    public Obfuscator<Integer> feasibilityCountObfuscator() {
        return new FeasibilityCachingLaplaceCountObfuscator(
                evaluationSettingsProvider.resultObfuscationLaplaceSensitivity(),
                evaluationSettingsProvider.resultObfuscationLaplaceEpsilon());
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
    public EvaluateRequestRate requestRateLimiter() {
        return new EvaluateRequestRate(new RateLimit(evaluationSettingsProvider.getRateLimitCount(),
                evaluationSettingsProvider.getRateLimitTimeIntervalDuration()), api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public RateLimitExceededTaskRejecter rateLimitExceededTaskRejecter() {
        return new RateLimitExceededTaskRejecter(api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public SetupEvaluationSettings setupEvaluationSettings() {
        return new SetupEvaluationSettings(evaluationSettingsProvider, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public DownloadFeasibilityResources downloadFeasibilityResources(
            EnhancedFhirWebserviceClientProvider enhancedFhirClientProvider) {
        return new DownloadFeasibilityResources(enhancedFhirClientProvider, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public StoreFeasibilityResources storeFeasibilityResources() {
        return new StoreFeasibilityResources(storeClient, api, new FeasibilityResourceCleaner());
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public EvaluateCqlMeasure evaluateCqlMeasure() {
        return new EvaluateCqlMeasure(storeClient, api);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public EvaluateStructuredQueryMeasure evaluateStructureQueryMeasure() {
        return new EvaluateStructuredQueryMeasure(flareWebserviceClient, api);
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
    public FeasibilityProcessPluginDeploymentStateListener deploymentStateListener() {
        return new FeasibilityProcessPluginDeploymentStateListener(evaluationSettingsProvider.evaluationStrategy(),
                storeClient, flareWebserviceClient);
    }
}
