/*
 * Copyright 2020, EnMasse authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */

package io.strimzi.systemtest.certs.openssl;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class CertPair implements Closeable {
    private final Path key;
    private final Path cert;
    private String subject;

    public CertPair(Path key, Path cert, String subject) {
        this.key = key;
        this.cert = cert;
        this.subject = subject;
    }

    public Path getKey() {
        return key;
    }

    public Path getCert() {
        return cert;
    }

    public String getSubject() {
        return subject;
    }

    @Override
    public void close() {
        try {
            if (key != null) {

                Files.delete(key);

                if (cert != null) {

                    Files.delete(cert);
                }
            }
        } catch (IOException e) {
                e.printStackTrace();
        }
    }
}
