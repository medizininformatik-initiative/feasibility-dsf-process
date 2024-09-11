package de.medizininformatik_initiative.process.feasibility.tools.generator;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.parser.IParser;
import dev.dsf.fhir.service.ReferenceCleaner;
import dev.dsf.fhir.service.ReferenceCleanerImpl;
import dev.dsf.fhir.service.ReferenceExtractor;
import dev.dsf.fhir.service.ReferenceExtractorImpl;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Organization;
import org.hl7.fhir.r4.model.StringType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Optional;

public class BundleGenerator {

    private static final Logger logger = LoggerFactory.getLogger(BundleGenerator.class);

    private final FhirContext fhirContext = FhirContext.forR4();
    private final ReferenceExtractor extractor = new ReferenceExtractorImpl();
    private final ReferenceCleaner cleaner = new ReferenceCleanerImpl(extractor);

    private Bundle dic1Bundle;
    private Bundle dic2Bundle;
    private Bundle dic3Bundle;
    private Bundle dic4Bundle;
    private Bundle zarsBundle;

    private Bundle brokerBundle;
    private Bundle brokerdic5Bundle;
    private Bundle brokerdic6Bundle;


    private Bundle readAndCleanBundle(Path bundleTemplateFile) {
        try (InputStream in = Files.newInputStream(bundleTemplateFile)) {
            Bundle bundle = newXmlParser().parseResource(Bundle.class, in);

            // FIXME hapi parser can't handle embedded resources and creates them while parsing bundles
            return cleaner.cleanReferenceResourcesIfBundle(bundle);
        } catch (IOException e) {
            logger.error("Error while reading bundle from " + bundleTemplateFile, e);
            throw new RuntimeException(e);
        }
    }

    private void writeBundle(Path bundleFile, Bundle bundle) {
        try (OutputStream out = Files.newOutputStream(bundleFile);
             OutputStreamWriter writer = new OutputStreamWriter(out)) {
            newXmlParser().encodeResourceToWriter(bundle, writer);
        } catch (IOException e) {
            logger.error("Error while writing bundle to " + bundleFile, e);
            throw new RuntimeException(e);
        }
    }

    private IParser newXmlParser() {
        IParser parser = fhirContext.newXmlParser();
        parser.setStripVersionsFromReferences(false);
        parser.setOverrideResourceIdWithBundleEntryFullUrl(false);
        parser.setPrettyPrint(true);
        return parser;
    }

    public void createDockerTestBundles(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        createDockerTestDic1Bundle(clientCertificateFilesByCommonName);
        createDockerTestDic2Bundle(clientCertificateFilesByCommonName);
        createDockerTestDic3Bundle(clientCertificateFilesByCommonName);
        createDockerTestDic4Bundle(clientCertificateFilesByCommonName);
        createDockerTestZarsBundle(clientCertificateFilesByCommonName);

        createDockerTestBrokerDic5Bundle(clientCertificateFilesByCommonName);
        createDockerTestBrokerDic6Bundle(clientCertificateFilesByCommonName);
        createDockerTestBrokerBundle(clientCertificateFilesByCommonName);
    }

    private void createDockerTestDic1Bundle(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Path bundleTemplateFile = Paths.get("src/main/resources/bundle-templates/dic-1-bundle.xml");
        logger.info("createDockerTestDic1Bundle: src/main/resources/bundle-templates/dic-1-bundle.xml");

        dic1Bundle = readAndCleanBundle(bundleTemplateFile);

        Organization organizationZars = (Organization) dic1Bundle.getEntry().get(0).getResource();
        setThumbprint(organizationZars, clientCertificateFilesByCommonName.get("zars-client"));

        Organization organizationDic1 = (Organization) dic1Bundle.getEntry().get(1).getResource();
        setThumbprint(organizationDic1, clientCertificateFilesByCommonName.get("dic-1-client"));

        writeBundle(Paths.get("bundle/dic-1-bundle.xml"), dic1Bundle);
    }

    private void setThumbprint(Organization organization, CertificateGenerator.CertificateFiles files) {
        logger.info("setThumbprint: " + organization.getIdentifier().get(0).getValue());
        organization
                .getExtensionByUrl("http://dsf.dev/fhir/StructureDefinition/extension-certificate-thumbprint")
                .setValue(new StringType(files.getCertificateSha512ThumbprintHex()));
    }

    private void createDockerTestDic2Bundle(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Path bundleTemplateFile = Paths.get("src/main/resources/bundle-templates/dic-2-bundle.xml");

        dic2Bundle = readAndCleanBundle(bundleTemplateFile);

        Organization organizationZars = (Organization) dic2Bundle.getEntry().get(0).getResource();
        setThumbprint(organizationZars, clientCertificateFilesByCommonName.get("zars-client"));

        Organization organizationDic2 = (Organization) dic2Bundle.getEntry().get(1).getResource();
        setThumbprint(organizationDic2, clientCertificateFilesByCommonName.get("dic-2-client"));

        writeBundle(Paths.get("bundle/dic-2-bundle.xml"), dic2Bundle);
    }

    private void createDockerTestDic3Bundle(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Path bundleTemplateFile = Paths.get("src/main/resources/bundle-templates/dic-3-bundle.xml");

        dic3Bundle = readAndCleanBundle(bundleTemplateFile);

        Organization organizationZars = (Organization) dic3Bundle.getEntry().get(0).getResource();
        setThumbprint(organizationZars, clientCertificateFilesByCommonName.get("zars-client"));

        Organization organizationDic3 = (Organization) dic3Bundle.getEntry().get(1).getResource();
        setThumbprint(organizationDic3, clientCertificateFilesByCommonName.get("dic-3-client"));

        writeBundle(Paths.get("bundle/dic-3-bundle.xml"), dic3Bundle);
    }

    private void createDockerTestDic4Bundle(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Path bundleTemplateFile = Paths.get("src/main/resources/bundle-templates/dic-4-bundle.xml");

        dic4Bundle = readAndCleanBundle(bundleTemplateFile);

        Organization organizationZars = (Organization) dic4Bundle.getEntry().get(0).getResource();
        setThumbprint(organizationZars, clientCertificateFilesByCommonName.get("zars-client"));

        Organization organizationDic4 = (Organization) dic4Bundle.getEntry().get(1).getResource();
        setThumbprint(organizationDic4, clientCertificateFilesByCommonName.get("dic-4-client"));

        writeBundle(Paths.get("bundle/dic-4-bundle.xml"), dic4Bundle);
    }

    private void createDockerTestZarsBundle(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Path bundleTemplateFile = Paths.get("src/main/resources/bundle-templates/zars-bundle.xml");

        zarsBundle = readAndCleanBundle(bundleTemplateFile);

        Organization organizationZars = (Organization) zarsBundle.getEntry().get(0).getResource();
        setThumbprint(organizationZars, clientCertificateFilesByCommonName.get("zars-client"));

        Organization organizationDic1 = (Organization) zarsBundle.getEntry().get(1).getResource();
        setThumbprint(organizationDic1, clientCertificateFilesByCommonName.get("dic-1-client"));

        Organization organizationDic2 = (Organization) zarsBundle.getEntry().get(2).getResource();
        setThumbprint(organizationDic2, clientCertificateFilesByCommonName.get("dic-2-client"));

        Organization organizationDic3 = (Organization) zarsBundle.getEntry().get(3).getResource();
        setThumbprint(organizationDic3, clientCertificateFilesByCommonName.get("dic-3-client"));

        Organization organizationDic4 = (Organization) zarsBundle.getEntry().get(4).getResource();
        setThumbprint(organizationDic4, clientCertificateFilesByCommonName.get("dic-4-client"));

        Organization organizationBroker = (Organization) zarsBundle.getEntry().get(5).getResource();
        setThumbprint(organizationBroker, clientCertificateFilesByCommonName.get("broker-client"));

        writeBundle(Paths.get("bundle/zars-bundle.xml"), zarsBundle);
    }

    private void createDockerTestBrokerBundle(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Path bundleTemplateFile = Paths.get("src/main/resources/bundle-templates/broker-bundle.xml");

        brokerBundle = readAndCleanBundle(bundleTemplateFile);

        Organization organizationBroker = (Organization) brokerBundle.getEntry().get(0).getResource();
        setThumbprint(organizationBroker, clientCertificateFilesByCommonName.get("broker-client"));

        Organization organizationZars = (Organization) brokerBundle.getEntry().get(1).getResource();
        setThumbprint(organizationZars, clientCertificateFilesByCommonName.get("zars-client"));

        Organization organizationBrokerDic5 = (Organization) brokerBundle.getEntry().get(2).getResource();
        setThumbprint(organizationBrokerDic5, clientCertificateFilesByCommonName.get("broker-dic-5-client"));

        Organization organizationBrokerDic6 = (Organization) brokerBundle.getEntry().get(3).getResource();
        setThumbprint(organizationBrokerDic6, clientCertificateFilesByCommonName.get("broker-dic-6-client"));

        writeBundle(Paths.get("bundle/broker-bundle.xml"), brokerBundle);
    }

    private void createDockerTestBrokerDic5Bundle(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Path bundleTemplateFile = Paths.get("src/main/resources/bundle-templates/broker-dic-5-bundle.xml");

        brokerdic5Bundle = readAndCleanBundle(bundleTemplateFile);

        Organization organizationBroker = (Organization) brokerdic5Bundle.getEntry().get(0).getResource();
        setThumbprint(organizationBroker, clientCertificateFilesByCommonName.get("broker-client"));

        Organization organizationBrokerDic5 = (Organization) brokerdic5Bundle.getEntry().get(1).getResource();
        setThumbprint(organizationBrokerDic5, clientCertificateFilesByCommonName.get("broker-dic-5-client"));

        writeBundle(Paths.get("bundle/broker-dic-5-bundle.xml"), brokerdic5Bundle);
    }

    private void createDockerTestBrokerDic6Bundle(Map<String, CertificateGenerator.CertificateFiles> clientCertificateFilesByCommonName) {
        Path bundleTemplateFile = Paths.get("src/main/resources/bundle-templates/broker-dic-6-bundle.xml");

        brokerdic6Bundle = readAndCleanBundle(bundleTemplateFile);

        Organization organizationBroker = (Organization) brokerdic6Bundle.getEntry().get(0).getResource();
        setThumbprint(organizationBroker, clientCertificateFilesByCommonName.get("broker-client"));

        Organization organizationBrokerDic6 = (Organization) brokerdic6Bundle.getEntry().get(1).getResource();
        setThumbprint(organizationBrokerDic6, clientCertificateFilesByCommonName.get("broker-dic-6-client"));

        writeBundle(Paths.get("bundle/broker-dic-6-bundle.xml"), brokerdic6Bundle);
    }

    public void copyDockerTestBundles() {
        Path dic1BundleFile = Paths.get("../../mii-process-feasibility-docker-test-setup/dic-1/fhir/conf/bundle.xml");
        logger.info("Copying fhir bundle to {}", dic1BundleFile);
        writeBundle(dic1BundleFile, dic1Bundle);

        Path dic2BundleFile = Paths.get("../../mii-process-feasibility-docker-test-setup/dic-2/fhir/conf/bundle.xml");
        logger.info("Copying fhir bundle to {}", dic2BundleFile);
        writeBundle(dic2BundleFile, dic2Bundle);

        Path dic3BundleFile = Paths.get("../../mii-process-feasibility-docker-test-setup/dic-3/fhir/conf/bundle.xml");
        logger.info("Copying fhir bundle to {}", dic3BundleFile);
        writeBundle(dic3BundleFile, dic3Bundle);

        Path dic4BundleFile = Paths.get("../../mii-process-feasibility-docker-test-setup/dic-4/fhir/conf/bundle.xml");
        logger.info("Copying fhir bundle to {}", dic4BundleFile);
        writeBundle(dic4BundleFile, dic4Bundle);

        Path zarsBundleFile = Paths.get("../../mii-process-feasibility-docker-test-setup/zars/fhir/conf/bundle.xml");
        logger.info("Copying fhir bundle to {}", zarsBundleFile);
        writeBundle(zarsBundleFile, zarsBundle);

        Path brokerDic5BundleFile = Paths.get("../../mii-process-feasibility-docker-test-setup/broker-dic-5/fhir/conf/bundle.xml");
        logger.info("Copying fhir bundle to {}", brokerDic5BundleFile);
        writeBundle(brokerDic5BundleFile, brokerdic5Bundle);

        Path brokerDic6BundleFile = Paths.get("../../mii-process-feasibility-docker-test-setup/broker-dic-6/fhir/conf/bundle.xml");
        logger.info("Copying fhir bundle to {}", brokerDic6BundleFile);
        writeBundle(brokerDic6BundleFile, brokerdic6Bundle);

        Path brokerBundleFile = Paths.get("../../mii-process-feasibility-docker-test-setup/broker/fhir/conf/bundle.xml");
        logger.info("Copying fhir bundle to {}", brokerBundleFile);
        writeBundle(brokerBundleFile, brokerBundle);
    }
}
