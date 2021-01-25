/*
 * Copyright 2020, EnMasse authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */

package io.strimzi.systemtest.certs.openssl;


import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import io.strimzi.systemtest.certs.BrokerCertBundle;
import io.strimzi.systemtest.certs.CertBundle;
import io.strimzi.test.executor.Exec;

public class OpenSSLUtil {
    public static final String DEFAULT_SUBJECT = "/O=strimzi-systemtests";

    public static CertPair createSelfSignedCert() throws IOException {
        return createSelfSignedCert(DEFAULT_SUBJECT);
    }

    public static CertPair createSelfSignedCert(String subject) throws IOException {
        Path key = null;
        Path cert = null;
        boolean success = false;
        try {
            key = Files.createTempFile("tls", ".key");
            cert = Files.createTempFile("tls", ".crt");

            success = Exec.exec("openssl", "req", "-new", "-days", "11000", "-x509", "-batch", "-nodes",
                    "-out", cert.toAbsolutePath().toString(),
                    "-keyout", key.toAbsolutePath().toString(),
                    "-subj",
                    subject).exitStatus();

            return new CertPair(key, cert, subject);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            if (!success) {

                if (key != null) {
                    Files.delete(key);
                }
                if (cert != null) {
                    Files.delete(cert);
                }
            }
        }
    }

    public static CertPair createStore(CertPair cert, String name) throws IOException {
        Path keystore = null;
        Path p12Store = null;
        boolean success = false;
        try {
            keystore = Files.createTempFile("tls", ".jks");
            p12Store = Files.createTempFile("tls", ".p12");
            success = Exec.exec("openssl", "pkcs12", "-export", "-passout", "pass:123456",
                    "-in", cert.getCert().toAbsolutePath().toString(), "-inkey", cert.getKey().toAbsolutePath().toString(),
                    "-name", name, "-out", p12Store.toAbsolutePath().toString()).exitStatus();

            Files.delete(keystore);
            success = Exec.exec("keytool", "-importkeystore", "-srcstorepass", "123456",
                    "-deststorepass", "123456", "-destkeystore", keystore.toAbsolutePath().toString(), "-srckeystore", p12Store.toAbsolutePath().toString(), "-srcstoretype", "PKCS12").exitStatus();

            return new CertPair(null, keystore, null);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            if (!success) {

                if (keystore != null) {
                    Files.delete(keystore);
                }
                if (p12Store != null) {
                    Files.delete(p12Store);
                }
            }
        }
    }

    public static CertSigningRequest createCsr(CertPair target) throws IOException {
        Path csr = null;
        boolean success = false;
        try {
            csr = Files.createTempFile("server", ".csr");
            success = Exec.exec("openssl", "req", "-new", "-batch", "-nodes", "-keyout", target.getKey().toAbsolutePath().toString(),
                    "-subj", target.getSubject(), "-out", csr.toAbsolutePath().toString()).exitStatus();
            return new CertSigningRequest(csr, target.getKey());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            if (!success) {
                if (csr != null) {
                    Files.delete(csr);
                }
            }
        }
    }

    public static CertPair signCsr(CertSigningRequest request, Collection<String> sans, CertPair ca) throws IOException {
        Path crt = null;
        boolean success = false;
        try {
            crt = Files.createTempFile("server", ".crt");
            if (sans.size() > 0) {
                String sansString = "subjectAltName=DNS:" + String.join(",DNS:", sans);
                success = Exec.exec("bash",
                        "-c",
                        "openssl x509 -req -extfile <(printf \"" + sansString + "\") -days 11000 -in " + request.getCsrFile().toAbsolutePath().toString() +
                                " -CA " + ca.getCert().toAbsolutePath() +
                                " -CAkey " + ca.getKey().toAbsolutePath() +
                                " -CAcreateserial -out " + crt.toAbsolutePath().toString()).exitStatus();
            } else {
                success = Exec.exec("openssl",
                        "x509",
                        "-req",
                        "-days",
                        "11000",
                        "-in",
                        request.getCsrFile().toAbsolutePath().toString(),
                        "-CA",
                        ca.getCert().toAbsolutePath().toString(),
                        "-CAkey",
                        ca.getKey().toAbsolutePath().toString(),
                        "-CAcreateserial",
                        "-out",
                        crt.toAbsolutePath().toString()).exitStatus();
            }
            return new CertPair(request.getKeyFile(), crt, null);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            if (!success) {
                if (crt != null) {
                    Files.delete(crt);
                }
            }
        }
    }

    public static CertPair downloadCert(String host, int port) throws IOException {
        Path cert = null;
        boolean success = false;
        try {
            cert = Files.createTempFile(String.format("host_%s:%d", host, port), ".crt");
            List<String> cmd = Arrays.asList("openssl", "s_client", "-crlf", "-showcerts", "-servername", host, "-connect", String.format("%s:%d", host, port));
            // TODO!!!
//            ExecutionResultData data = Exec.exec("GET / HTTP/1.1\n", cmd);
//            Files.writeString(cert.toPath(), data.getStdOut());
//            success = data.exitStatus();
            return new CertPair(null, cert, null);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            if (!success) {
                if (cert != null) {
                    Files.delete(cert);
                }
            }
        }
    }

    // Root CA
    // Intermediary CA
    // Cluster CA cert/keys
    // Clients CA cert/keys
    // TODO
    public static CertBundle createCertBundle(String cn) throws Exception {
        CertPair ca = createSelfSignedCert();
        CertPair cert = createSelfSignedCert(DEFAULT_SUBJECT + "/CN=" + cn);
        CertSigningRequest csr = createCsr(cert);
        cert = signCsr(csr, Collections.emptyList(), ca);
        try {
            return new CertBundle(Files.readString(ca.getCert(), StandardCharsets.UTF_8),
                    Files.readString(cert.getKey(), StandardCharsets.UTF_8),
                    Files.readString(cert.getCert(), StandardCharsets.UTF_8));
        } finally {
            deleteFiles(ca.getCert(), ca.getKey(), cert.getKey(), cert.getCert());
        }
    }

    public static BrokerCertBundle createBrokerCertBundle(String cn) throws Exception {
        // Generate CA used to sign certs
        CertPair ca = createSelfSignedCert();
        try {
            // Create broker certs and put into keystore
            CertPair broker = createSelfSignedCert(DEFAULT_SUBJECT + "/CN=" + cn);
            CertSigningRequest brokerCsr = createCsr(broker);
            broker = signCsr(brokerCsr, Collections.emptyList(), ca);
            Path brokerKeystore = createStore(broker, "broker").getCert();

            // Generate truststore with client cert and put into truststore
            CertPair client = createSelfSignedCert(DEFAULT_SUBJECT);
            CertSigningRequest clientCsr = createCsr(client);
            client = signCsr(clientCsr, Collections.emptyList(), ca);

            //import client cert into broker TRUSTSTORE
            Path brokerTrustStore = createStore(client, "client").getCert();

            try {
                //return ca.crt keystore and truststore
                return new BrokerCertBundle(Files.readAllBytes(ca.getCert()),
                        Files.readAllBytes(brokerKeystore),
                        Files.readAllBytes(brokerTrustStore),
                        Files.readAllBytes(client.getCert()),
                        Files.readAllBytes(client.getKey()));
            } finally {
                deleteFiles(broker.getCert(), broker.getKey(), client.getCert(), client.getKey());
            }

        } finally {
            deleteFiles(ca.getCert(), ca.getKey());
        }
    }

    private static void deleteFiles(Path... files) {
        for (Path file : files) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
