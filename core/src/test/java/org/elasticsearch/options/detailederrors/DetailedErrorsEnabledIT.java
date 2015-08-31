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

package org.elasticsearch.options.detailederrors;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.node.Node;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.ESIntegTestCase.ClusterScope;
import org.elasticsearch.test.ESIntegTestCase.Scope;
import org.elasticsearch.test.rest.client.http.HttpResponse;
import org.junit.Test;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * Tests that by default the error_trace parameter can be used to show stacktraces
 */
@ClusterScope(scope = Scope.TEST, numDataNodes = 1)
public class DetailedErrorsEnabledIT extends ESIntegTestCase {

    // Build our cluster settings
    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        return Settings.settingsBuilder()
                .put(super.nodeSettings(nodeOrdinal))
                .put(Node.HTTP_ENABLED, true)
                .build();
    }

    @Test
    public void testThatErrorTraceWorksByDefault() throws Exception {
        // Make the HTTP request
        HttpResponse response = httpClient()
                .path("/")
                .addParam("error_trace", "true")
                .method("DELETE")
                .execute();

        assertThat(response.getHeader("Content-Type"), containsString("application/json"));
        assertThat(response.getBody(), containsString("\"error_trace\":{\"message\":\"Validation Failed"));

        // Make the HTTP request
        response = httpClient()
                .path("/")
                .method("DELETE")
                .execute();

        assertThat(response.getHeader("Content-Type"), containsString("application/json"));
        assertThat(response.getBody(), not(containsString("\"stack_trace\":\"[Validation Failed: 1: index / indices is missing;]; nested: ActionRequestValidationException[Validation Failed: 1:")));
    }
}
