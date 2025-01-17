package de.medizininformatik_initiative.process.feasibility.spring.config;

import de.medizininformatik_initiative.process.feasibility.EvaluationStrategy;
import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BaseConfigTest {

    @Mock private AbstractEnvironment environment;
    @Mock private MutablePropertySources propertySources;
    @Mock private EnumerablePropertySource<String> propertySource;

    @Test
    void emptySettingsWithNoConfig() {
        BaseConfig baseConfig = new BaseConfig();
        baseConfig.configuration = null;
        baseConfig.configurationFile = null;

        FeasibilitySettings settings = baseConfig.storeSettings();

        assertThat(settings.networks()).isEmpty();
        assertThat(settings.stores()).isEmpty();
    }

    @Test
    void errorOnNonReadableConfigFile() {
        var baseConfig = new BaseConfig();
        var nonExistingFile = "/non/existing/configuration/file";
        baseConfig.configuration = null;
        baseConfig.configurationFile = nonExistingFile;

        assertThatThrownBy(() -> baseConfig.storeSettings())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Configuration file '%s' could not be loaded.".formatted(nonExistingFile));
    }

    @Test
    void errorOnEmptyConfigFile() throws IOException {
        var baseConfig = new BaseConfig();
        var configFile = Files.createTempFile("test", ".yml");
        Files.writeString(configFile, "");
        baseConfig.configuration = null;
        baseConfig.configurationFile = configFile.toString();
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        assertThatThrownBy(() -> baseConfig.storeSettings())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Configuration could not be parsed.");
    }

    @Test
    void emptySettingsOnEmptyStores() throws IOException {
        var baseConfig = new BaseConfig();
        baseConfig.configuration = """
                stores:
                    """;
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        FeasibilitySettings settings = baseConfig.storeSettings();

        assertThat(settings.networks()).isEmpty();
        assertThat(settings.stores()).isEmpty();
    }
    @Test
    void emptySettingsOnEmptyNetworks() throws IOException {
        var baseConfig = new BaseConfig();
        baseConfig.configuration = """
                networks:
                """;
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        FeasibilitySettings settings = baseConfig.storeSettings();

        assertThat(settings.networks()).isEmpty();
        assertThat(settings.stores()).isEmpty();
    }

    @Test
    void emptySettingsOnEmptyStoresAndNetworks() throws IOException {
        var baseConfig = new BaseConfig();
        baseConfig.configuration = """
                stores:
                networks:
                """;
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        FeasibilitySettings settings = baseConfig.storeSettings();

        assertThat(settings.networks()).isEmpty();
        assertThat(settings.stores()).isEmpty();
    }

    @Test
    void envVarsAreReplaced() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId = "foo";
        var baseUrl = URI.create("http://foo.bar");
        var baseUrlEnvVar = "BASE_URL";
        var evaluationStrategy = "cql";
        var evaluationStrategyEnvVar = "EVAL_STRATEGY";
        baseConfig.configuration = """
                stores:
                  %s:
                    baseUrl: ${%s}
                    evaluationStrategy: ${%s}
                """.formatted(storeId, baseUrlEnvVar, evaluationStrategyEnvVar);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of(propertySource).stream());
        when(propertySource.getPropertyNames()).thenReturn(new String[] { baseUrlEnvVar, evaluationStrategyEnvVar });
        when(environment.getProperty(baseUrlEnvVar)).thenReturn(baseUrl.toString());
        when(environment.getProperty(evaluationStrategyEnvVar)).thenReturn(evaluationStrategy);

        FeasibilitySettings settings = baseConfig.storeSettings();

        assertThat(settings.networks()).isEmpty();
        assertThat(settings.stores())
                .hasSize(1)
                .containsKey(storeId);
        assertThat(settings.stores().get(storeId).baseUrl()).isEqualTo(baseUrl.toURL());
        assertThat(settings.stores().get(storeId).evaluationStrategy()).isEqualTo(EvaluationStrategy.CQL);
    }

    @Test
    void singleStore() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId = "foo";
        var baseUrl = URI.create("http://foo.bar");
        baseConfig.configuration = """
                stores:
                  %s:
                    baseUrl: %s
                    evaluationStrategy: cql
                """.formatted(storeId, baseUrl);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        FeasibilitySettings settings = baseConfig.storeSettings();

        assertThat(settings.networks()).isEmpty();
        assertThat(settings.stores())
                .hasSize(1)
                .containsKey(storeId);
        assertThat(settings.stores().get(storeId).baseUrl()).isEqualTo(baseUrl.toURL());
        assertThat(settings.stores().get(storeId).evaluationStrategy()).isEqualTo(EvaluationStrategy.CQL);
    }

    @Test
    void twoStores() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId1 = "foo";
        var baseUrl1 = URI.create("http://foo.bar");
        var storeId2 = "bar";
        var baseUrl2 = URI.create("http://bar.foo");
        baseConfig.configuration = """
                stores:
                  %s:
                    baseUrl: %s
                    evaluationStrategy: cql
                  %s:
                    baseUrl: %s
                    evaluationStrategy: ccdl
                """.formatted(storeId1, baseUrl1, storeId2, baseUrl2);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        FeasibilitySettings settings = baseConfig.storeSettings();

        assertThat(settings.networks()).isEmpty();
        assertThat(settings.stores())
                .hasSize(2)
                .containsKeys(storeId1, storeId2);
        assertThat(settings.stores().get(storeId1).baseUrl()).isEqualTo(baseUrl1.toURL());
        assertThat(settings.stores().get(storeId1).evaluationStrategy()).isEqualTo(EvaluationStrategy.CQL);
        assertThat(settings.stores().get(storeId2).baseUrl()).isEqualTo(baseUrl2.toURL());
        assertThat(settings.stores().get(storeId2).evaluationStrategy()).isEqualTo(EvaluationStrategy.CCDL);
    }

    @Test
    void errorNetworkHasUnknownStoreId() throws IOException {
        var baseConfig = new BaseConfig();
        var networkId = "foo.bar";
        var storeId = "foo";
        baseConfig.configuration = """
                networks:
                  %s:
                    stores:
                    - %s
                """.formatted(networkId, storeId);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        assertThatThrownBy(() -> baseConfig.storeSettings())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Configuration contains errors:")
                .hasMessageContaining("Network '%s' references unknown store id '%s'".formatted(networkId, storeId));
    }

    @Test
    void errorStoreMissingEvaluationStrategy() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId = "foo";
        baseConfig.configuration = """
                stores:
                  %s:
                    baseUrl: http://foo.bar
                """.formatted(storeId);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        assertThatThrownBy(() -> baseConfig.storeSettings())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Configuration contains errors:")
                .hasMessageContaining("Store '%s' has no evaluationStrategy set.".formatted(storeId));
    }

    @Test
    void errorStoreHavingMultipleAuthenticationMethods() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId = "foo";
        baseConfig.configuration = """
                stores:
                  %s:
                    baseUrl: http://foo.bar
                    evaluationStrategy: ccdl
                    basicAuth:
                      username: foo
                      password: bar
                    bearerAuth:
                      token: foobar
                """.formatted(storeId);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        assertThatThrownBy(() -> baseConfig.storeSettings())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Configuration contains errors:")
                .hasMessageContaining("Store '%s' contains more than one authentication method".formatted(storeId))
                .hasMessageContainingAll("bearerAuth", "basicAuth");
    }

    @Test
    void errorOnEmptyPasswordForBasicAuth() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId = "foo";
        baseConfig.configuration = """
                stores:
                  %s:
                    baseUrl: http://foo.bar
                    evaluationStrategy: ccdl
                    basicAuth:
                      username: foo
                      password: ""
                """.formatted(storeId);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        assertThatThrownBy(() -> baseConfig.storeSettings())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Configuration contains errors:")
                .hasMessageContaining(
                        "Store '%s' has no password set for basicAuth.".formatted(storeId));
    }

    @Test
    void errorOnInvalidPasswordFileForBasicAuth() throws IOException {
        var baseConfig = new BaseConfig();
        var nonExistingPasswordFile = "/non/existing/password/file";
        baseConfig.configuration = """
                stores:
                  foo:
                    baseUrl: http://foo.bar
                    evaluationStrategy: ccdl
                    basicAuth:
                      username: foo
                      passwordFile: %s
                """.formatted(nonExistingPasswordFile);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        assertThatThrownBy(() -> baseConfig.storeSettings())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Configuration could not be parsed.")
                .hasStackTraceContaining(
                        "Could not read password file '%s' for basicAuth.".formatted(nonExistingPasswordFile));
    }

    @Test
    void networkContainsAllStores() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId1 = "foo";
        var storeId2 = "bar";
        String networkId = "foo.bar";
        baseConfig.configuration = """
                stores:
                  %1$s:
                    baseUrl: http://foo.bar
                    evaluationStrategy: ccdl
                  %2$s:
                    baseUrl: http://foo.bar
                    evaluationStrategy: ccdl

                networks:
                  %3$s:
                    obfuscate: true
                    stores:
                    - %1$s
                    - %2$s
                """.formatted(storeId1, storeId2, networkId);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        var settings = baseConfig.storeSettings();

        assertThat(settings.networks()).hasSize(1);
        assertThat(settings.networks()).containsKey(networkId);
        assertThat(settings.networks().get(networkId).storeIds()).contains(storeId1, storeId2);
    }

    @Test
    void obfuscationSettingIsApplied() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId = "foo";
        String networkId1 = "foo.bar";
        String networkId2 = "bar.foo";
        baseConfig.configuration = """
                stores:
                  %1$s:
                    baseUrl: http://foo.bar
                    evaluationStrategy: ccdl

                networks:
                  %2$s:
                    obfuscate: true
                    stores:
                    - %1$s
                  %3$s:
                    obfuscate: false
                    stores:
                    - %1$s
                """.formatted(storeId, networkId1, networkId2);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        var settings = baseConfig.storeSettings();

        assertThat(settings.networks()).hasSize(2);
        assertThat(settings.networks()).containsKeys(networkId1, networkId2);
        assertThat(settings.networks().get(networkId1).obfuscate()).isTrue();
        assertThat(settings.networks().get(networkId2).obfuscate()).isFalse();
    }

    @Test
    void obfuscationIsEnableByDefault() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId = "foo";
        String networkId = "foo.bar";
        baseConfig.configuration = """
                stores:
                  %1$s:
                    baseUrl: http://foo.bar
                    evaluationStrategy: ccdl

                networks:
                  %2$s:
                    stores:
                    - %1$s
                """.formatted(storeId, networkId);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        var settings = baseConfig.storeSettings();

        assertThat(settings.networks()).hasSize(1);
        assertThat(settings.networks()).containsKey(networkId);
        assertThat(settings.networks().get(networkId).obfuscate()).isTrue();
    }

    @Test
    void defaultRateLimitIsSet() throws IOException {
        var baseConfig = new BaseConfig();
        var storeId = "foo";
        String networkId = "foo.bar";
        baseConfig.configuration = """
                stores:
                  %1$s:
                    baseUrl: http://foo.bar
                    evaluationStrategy: ccdl

                networks:
                  %2$s:
                    stores:
                    - %1$s
                """.formatted(storeId, networkId);
        baseConfig.configurationFile = null;
        baseConfig.environment = environment;
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.stream()).thenReturn(List.<PropertySource<?>>of().stream());

        var settings = baseConfig.storeSettings();

        assertThat(settings.networks()).hasSize(1);
        assertThat(settings.networks()).containsKey(networkId);
        assertThat(settings.networks().get(networkId).rateLimit()).isNotNull();
    }
}
