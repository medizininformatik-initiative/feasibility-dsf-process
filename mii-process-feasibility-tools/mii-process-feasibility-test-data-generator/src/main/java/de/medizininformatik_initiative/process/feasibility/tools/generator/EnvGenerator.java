package de.medizininformatik_initiative.process.feasibility.tools.generator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class EnvGenerator {
    private static final Logger logger = LoggerFactory.getLogger(EnvGenerator.class);

    private static final String USER_THUMBPRINTS = "USER_THUMBPRINTS";
    private static final String USER_THUMBPRINTS_PERMANENTDELETE = "USER_THUMBPRINTS_PERMANENT_DELETE";

    private static final class EnvEntry {
        final String userThumbprintsVariableName;
        final Stream<String> userThumbprints;
        final String userThumbprintsPermanentDeleteVariableName;
        final Stream<String> userThumbprintsPermanentDelete;

        EnvEntry(String userThumbprintsVariableName, Stream<String> userThumbprints) {
            this.userThumbprintsVariableName = userThumbprintsVariableName;
            this.userThumbprints = userThumbprints;
            this.userThumbprintsPermanentDeleteVariableName = null;
            this.userThumbprintsPermanentDelete = null;
        }

        EnvEntry(String userThumbprintsVariableName, Stream<String> userThumbprints,
                String userThumbprintsPermanentDeleteVariableName, Stream<String> userThumbprintsPermanentDelete) {
            this.userThumbprintsVariableName = userThumbprintsVariableName;
            this.userThumbprints = userThumbprints;
            this.userThumbprintsPermanentDeleteVariableName = userThumbprintsPermanentDeleteVariableName;
            this.userThumbprintsPermanentDelete = userThumbprintsPermanentDelete;
        }
    }

    public void generateAndWriteDockerTestFhirEnvFiles(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Stream<String> zarsUserThumbprints = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "zars-client",
                "Webbrowser Test User");
        Stream<String> zarsUserThumbprintsPermanentDelete = filterAndMapToThumbprint(clientCertificateFilesByCommonName,
                "zars-client", "Webbrowser Test User");

        Stream<String> dic1UserThumbprints = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "dic-1-client",
                "Webbrowser Test User");
        Stream<String> dic1UserThumbprintsPermanentDelete = filterAndMapToThumbprint(clientCertificateFilesByCommonName,
                "dic-1-client", "Webbrowser Test User");

        Stream<String> dic2UserThumbprints = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "dic-2-client",
                "Webbrowser Test User");
        Stream<String> dic2UserThumbprintsPermanentDelete = filterAndMapToThumbprint(clientCertificateFilesByCommonName,
                "dic-2-client", "Webbrowser Test User");

        Stream<String> dic3UserThumbprints = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "dic-3-client",
                "Webbrowser Test User");
        Stream<String> dic3UserThumbprintsPermanentDelete = filterAndMapToThumbprint(clientCertificateFilesByCommonName,
                "dic-3-client", "Webbrowser Test User");

        Stream<String> dic4UserThumbprints = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "dic-4-client",
                "Webbrowser Test User");
        Stream<String> dic4UserThumbprintsPermanentDelete = filterAndMapToThumbprint(clientCertificateFilesByCommonName,
                "dic-4-client", "Webbrowser Test User");

        Stream<String> webBrowserTestUserThumbprint = filterAndMapToThumbprint(clientCertificateFilesByCommonName,
                "Webbrowser Test User");

        Stream<String> brokerDic5UserThumbprints = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "broker-dic-5-client",
                "Webbrowser Test User");
        Stream<String> brokerDic5UserThumbprintsPermanentDelete = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "broker-dic-5-client",
                "Webbrowser Test User");

        Stream<String> brokerDic6UserThumbprintsThumbprints = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "broker-dic-6-client",
                "Webbrowser Test User");
        Stream<String> brokerDic6UserThumbprintsPermanentDelete = filterAndMapToThumbprint(clientCertificateFilesByCommonName,
                "broker-dic-6-client", "Webbrowser Test User");

        Stream<String> brokerUserThumbprints = filterAndMapToThumbprint(clientCertificateFilesByCommonName, "broker-client",
                "Webbrowser Test User");
        Stream<String> brokerUserThumbprintsPermanentDelete = filterAndMapToThumbprint(clientCertificateFilesByCommonName,
                "broker-client", "Webbrowser Test User");

        List<EnvEntry> entries = List.of(
                new EnvEntry("ZARS_" + USER_THUMBPRINTS, zarsUserThumbprints, "ZARS_" + USER_THUMBPRINTS_PERMANENTDELETE,
                        zarsUserThumbprintsPermanentDelete),

                new EnvEntry("DIC_1_" + USER_THUMBPRINTS, dic1UserThumbprints, "DIC_1_" + USER_THUMBPRINTS_PERMANENTDELETE,
                        dic1UserThumbprintsPermanentDelete),

                new EnvEntry("DIC_2_" + USER_THUMBPRINTS, dic2UserThumbprints, "DIC_2_" + USER_THUMBPRINTS_PERMANENTDELETE,
                        dic2UserThumbprintsPermanentDelete),

                new EnvEntry("DIC_3_" + USER_THUMBPRINTS, dic3UserThumbprints, "DIC_3_" + USER_THUMBPRINTS_PERMANENTDELETE,
                        dic3UserThumbprintsPermanentDelete),

                new EnvEntry("DIC_4_" + USER_THUMBPRINTS, dic4UserThumbprints, "DIC_4_" + USER_THUMBPRINTS_PERMANENTDELETE,
                        dic4UserThumbprintsPermanentDelete),

                new EnvEntry("BROKER_DIC_5_" + USER_THUMBPRINTS, brokerDic5UserThumbprints, "BROKER_DIC_5_" + USER_THUMBPRINTS_PERMANENTDELETE,
                        brokerDic5UserThumbprintsPermanentDelete),

                new EnvEntry("BROKER_DIC_6_" + USER_THUMBPRINTS, brokerDic6UserThumbprintsThumbprints, "BROKER_DIC_6_" + USER_THUMBPRINTS_PERMANENTDELETE,
                        brokerDic6UserThumbprintsPermanentDelete),

                new EnvEntry("BROKER_" + USER_THUMBPRINTS, brokerUserThumbprints, "BROKER_" + USER_THUMBPRINTS_PERMANENTDELETE,
                        brokerUserThumbprintsPermanentDelete),

                new EnvEntry("WEBBROWSER_TEST_USER_THUMBPRINT", webBrowserTestUserThumbprint));

        writeEnvFile(Paths.get("../../mii-process-feasibility-docker-test-setup/.env"), entries);
    }

    private Stream<String> filterAndMapToThumbprint(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName,
                                                    String... commonNames) {
        return clientCertificateFilesByCommonName.entrySet().stream()
                .filter(entry -> Arrays.asList(commonNames).contains(entry.getKey()))
                .sorted(Comparator.comparing(e -> Arrays.asList(commonNames).indexOf(e.getKey()))).map(Map.Entry::getValue)
                .map(CertificateGenerator.CertificateFiles::getCertificateSha512ThumbprintHex);
    }

    private void writeEnvFile(Path target, List<? extends EnvEntry> entries) {
        StringBuilder builder = new StringBuilder();

        for (int i = 0; i < entries.size(); i++) {
            EnvEntry entry = entries.get(i);

            builder.append(entry.userThumbprintsVariableName);
            builder.append('=');
            builder.append(entry.userThumbprints.collect(Collectors.joining(",")));

            if (entry.userThumbprintsPermanentDeleteVariableName != null
                    && entry.userThumbprintsPermanentDelete != null) {
                builder.append('\n');
                builder.append(entry.userThumbprintsPermanentDeleteVariableName);
                builder.append('=');
                builder.append(entry.userThumbprintsPermanentDelete.collect(Collectors.joining(",")));
            }

            if ((i + 1) < entries.size())
                builder.append("\n\n");
        }

        try {
            logger.info("Writing .env file to {}", target.toString());
            Files.writeString(target, builder.toString());
        } catch (IOException e) {
            logger.error("Error while writing .env file to " + target, e);
            throw new RuntimeException(e);
        }
    }
}
