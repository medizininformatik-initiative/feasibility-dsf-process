package de.medizininformatik_initiative.process.feasibility.spring.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Configuration
public class BaseConfig {

    private static final Pattern ENV_VAR_PATTERN = Pattern.compile("\\$\\{\\w+\\}");

    private static final Logger logger = LoggerFactory.getLogger(BaseConfig.class);

    @Value("${de.medizininformatik_initiative.feasibility_dsf_process.configuration.file:#{null}}")
    String configurationFile;

    @Value("${de.medizininformatik_initiative.feasibility_dsf_process.configuration:#{null}}")
    String configuration;

    @Autowired Environment environment;

    @Bean
    FeasibilitySettings storeSettings() {
        if ((configurationFile == null || configurationFile.isBlank())
                && (configuration == null || configuration.isBlank())) {
            return new FeasibilitySettings(Map.of(), Map.of());
        } else {
            var config = configuration;
            if ((config == null || config.isBlank())) {
                try {
                    logger.debug("Loading configuration file '{}'.", configurationFile);
                    config = Files.readString(Paths.get(configurationFile));
                } catch (IOException e) {
                    throw new IllegalArgumentException(
                            "Configuration file '%s' could not be loaded.".formatted(configurationFile),
                            e);
                }
            }
            var substitutedConfig = substituteEnvironmentVariables(config);
            var settings = parseConfig(substitutedConfig, buildSettingsMapper());
            var errors = settings.validate();

            if (errors.isEmpty()) {
                return settings;
            } else {
                throw new IllegalArgumentException(
                        "Configuration contains errors: %s".formatted(errors));
            }
        }
    }

    private FeasibilitySettings parseConfig(String substitutedConfig, YAMLMapper mapper) {
        try {
            return mapper.readValue(substitutedConfig, FeasibilitySettings.class);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Configuration could not be parsed.", e);
        }
    }

    @Bean
    Map<String, Set<String>> networkStores(FeasibilitySettings settings) {
        return settings.networks()
                .entrySet()
                .stream()
                .collect(Collectors.toMap(e -> e.getKey(), e -> Set.copyOf(e.getValue().storeIds())));
    }

    private String substituteEnvironmentVariables(String config) {
        var envVars = ((AbstractEnvironment) environment).getPropertySources().stream()
                .filter(ps -> ps instanceof EnumerablePropertySource)
                .map(EnumerablePropertySource.class::cast)
                .flatMap(eps -> Arrays.stream(eps.getPropertyNames()))
                .collect(Collectors.toMap(n -> n, n -> getProperty(n)))
                .entrySet()
                .stream()
                .filter(e -> e.getValue().isPresent())
                .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue().get()));
        var oldConfig = "";
        while (ENV_VAR_PATTERN.matcher(config).find() && !oldConfig.contentEquals(config)) {
            oldConfig = config;
            config = envVars.entrySet()
                    .stream()
                    .reduce(config, (c, e) -> c.replaceAll("\\$\\{%s\\}".formatted(e.getKey()), e.getValue()),
                    (s1, s2) -> s1);
        }
        return config;
    }

    private Optional<String> getProperty(String name) {
        try {
            return Optional.ofNullable(environment.getProperty(name));
        } catch (IllegalArgumentException e) {
            logger.debug("Could not get environment variable '%s'.".formatted(name), e);
            return Optional.empty();
        }
    }

    private YAMLMapper buildSettingsMapper() {
        return YAMLMapper.builder()
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
                .addModule(new JavaTimeModule())
                .build();
    }
}
