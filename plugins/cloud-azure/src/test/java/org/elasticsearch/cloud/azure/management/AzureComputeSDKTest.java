/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.cloud.azure.management;

import com.microsoft.windowsazure.Configuration;
import com.microsoft.windowsazure.core.utils.KeyStoreType;
import com.microsoft.windowsazure.management.compute.ComputeManagementClient;
import com.microsoft.windowsazure.management.compute.ComputeManagementService;
import com.microsoft.windowsazure.management.configuration.ManagementConfiguration;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.bootstrap.JarHell;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.test.ESTestCase;

import java.io.FilePermission;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.ProtectionDomain;
import java.security.SecurityPermission;
import java.util.PropertyPermission;

public class AzureComputeSDKTest extends ESTestCase {

    public void testCreateConfiguration() throws URISyntaxException, IOException {

        final String keystore = "/keys/azurekeystore.pkcs12";

        final Configuration configuration = ManagementConfiguration.configure(null,
            new Configuration(),
            new URI("https://management.core.windows.net/"),
            "JSDQKHJHHJDHSJKH",
            keystore,
            "PPPPP",
            KeyStoreType.pkcs12);


        // check that its not unprivileged code like a script
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<ComputeManagementClient>() {
                @Override
                public ComputeManagementClient run() {
                    ComputeManagementClient client = ComputeManagementService.create(configuration);
                    return client;
                }
            }, new AccessControlContext(new ProtectionDomain[] {
                    new ProtectionDomain(null, getRestrictedPermissions(keystore))
                }
            ));
        } catch (PrivilegedActionException e) {
            // checked exception from Azure SDK: unbox it
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            } else {
                throw new AssertionError(cause);
            }
        }
    }

    static PermissionCollection getRestrictedPermissions(String keystore) {
        Permissions perms = new Permissions();
        perms.add(new RuntimePermission("getenv.test.mode"));
        perms.add(new FilePermission(keystore, "read"));
        perms.add(new PropertyPermission("java.specification.version", "read"));
        perms.setReadOnly();

        return perms;
    }

}
