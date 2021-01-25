/*
 * Copyright 2017-2018, EnMasse authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.systemtest.certs.openssl;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class CertSigningRequest implements Closeable {
    private final Path csrFile;
    private final Path keyFile;

    CertSigningRequest(Path csrFile, Path keyFile) {
        this.csrFile = csrFile;
        this.keyFile = keyFile;
    }

    public Path getCsrFile() {
        return csrFile;
    }

    public Path getKeyFile() {
        return keyFile;
    }

    @Override
    public void close() throws IOException {
        Files.delete(csrFile);
        Files.delete(keyFile);
    }
}
