/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.thoughtworks.xstream.io.binary.BinaryStreamReader;
import com.thoughtworks.xstream.io.binary.BinaryStreamWriter;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 * Tests for the App Roles mode feature.
 *
 * <p>Categories:
 * <ul>
 *   <li>Category 1: AzureAdUser.setAuthoritiesFromAppRoles (unit)</li>
 *   <li>Category 2: Converter marshal/unmarshal for useAppRoles (unit)</li>
 *   <li>Category 3: Configuration persistence across restarts (integration)</li>
 * </ul>
 */
class AppRolesTest {

    // ═══════════════════════════════════════════════════════════════════════
    // Category 1 — AzureAdUser.setAuthoritiesFromAppRoles
    // ═══════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("1. AzureAdUser App Roles Authorities")
    class AzureAdUserAppRolesTest {

        private AzureAdUser createTestUser() {
            JwtClaims claims = new JwtClaims();
            claims.setClaim("name", "Test User");
            claims.setClaim("upn", "test@example.com");
            claims.setClaim("tid", "test-tenant-id");
            claims.setClaim("oid", "test-object-id");
            claims.setClaim("email", "test@example.com");
            claims.setClaim("groups", Collections.emptyList());
            return AzureAdUser.createFromJwt(claims);
        }

        @Test
        @DisplayName("1.1 App roles are mapped to SimpleGrantedAuthority")
        void testAppRolesMappedToAuthorities() {
            AzureAdUser user = createTestUser();
            List<String> roles = Arrays.asList("jenkins-admin", "jenkins-deployer");

            user.setAuthoritiesFromAppRoles(roles, user.getUniqueName());

            List<String> authorityStrings = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            assertTrue(authorityStrings.contains("jenkins-admin"),
                    "Should contain jenkins-admin role");
            assertTrue(authorityStrings.contains("jenkins-deployer"),
                    "Should contain jenkins-deployer role");
        }

        @Test
        @DisplayName("1.2 AUTHENTICATED_AUTHORITY2 is always included")
        void testAuthenticatedAuthorityAlwaysIncluded() {
            AzureAdUser user = createTestUser();
            List<String> roles = Arrays.asList("jenkins-admin");

            user.setAuthoritiesFromAppRoles(roles, user.getUniqueName());

            List<String> authorityStrings = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            assertTrue(authorityStrings.contains(SecurityRealm.AUTHENTICATED_AUTHORITY2.getAuthority()),
                    "Should contain authenticated authority");
        }

        @Test
        @DisplayName("1.3 Object ID is included as authority")
        void testObjectIdIncludedAsAuthority() {
            AzureAdUser user = createTestUser();
            user.setAuthoritiesFromAppRoles(Collections.emptyList(), user.getUniqueName());

            List<String> authorityStrings = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            assertTrue(authorityStrings.contains("test-object-id"),
                    "Should contain the user's object ID");
        }

        @Test
        @DisplayName("1.4 UPN is included as authority")
        void testUpnIncludedAsAuthority() {
            AzureAdUser user = createTestUser();
            user.setAuthoritiesFromAppRoles(Collections.emptyList(), "test@example.com");

            List<String> authorityStrings = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            assertTrue(authorityStrings.contains("test@example.com"),
                    "Should contain the user's UPN");
        }

        @Test
        @DisplayName("1.5 Empty roles list results in only system authorities")
        void testEmptyRolesListResultsInSystemAuthorities() {
            AzureAdUser user = createTestUser();
            user.setAuthoritiesFromAppRoles(Collections.emptyList(), user.getUniqueName());

            // Should have exactly 3 authorities: authenticated, objectID, UPN
            assertEquals(3, user.getAuthorities().size(),
                    "Should have exactly 3 system authorities (authenticated, objectID, UPN)");
        }

        @Test
        @DisplayName("1.6 Multiple roles produce correct authority count")
        void testMultipleRolesCorrectAuthorityCount() {
            AzureAdUser user = createTestUser();
            List<String> roles = Arrays.asList("role-a", "role-b", "role-c");

            user.setAuthoritiesFromAppRoles(roles, user.getUniqueName());

            // 3 roles + 3 system authorities = 6
            assertEquals(6, user.getAuthorities().size(),
                    "Should have 3 role authorities + 3 system authorities");
        }

        @Test
        @DisplayName("1.7 setAuthoritiesFromAppRoles does not affect existing setAuthorities method")
        void testAppRolesDoNotAffectGraphAuthorities() {
            AzureAdUser user = createTestUser();

            // First set via app roles
            user.setAuthoritiesFromAppRoles(Arrays.asList("jenkins-admin"), user.getUniqueName());
            assertTrue(user.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("jenkins-admin")));

            // Then set via Graph groups (existing method)
            user.setAuthorities(Collections.emptyList(), user.getUniqueName());
            assertFalse(user.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("jenkins-admin")),
                    "Graph setAuthorities should replace app roles authorities");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Category 2 — Converter marshal/unmarshal for useAppRoles
    // ═══════════════════════════════════════════════════════════════════════

    @Nested
    @WithJenkins
    @DisplayName("2. Converter UseAppRoles Persistence")
    class ConverterAppRolesTest {

        @Test
        @DisplayName("2.1 useAppRoles=true is persisted through marshal/unmarshal")
        void testUseAppRolesTruePersisted() {
            BinaryStreamWriter writer = null;
            BinaryStreamReader reader = null;
            try {
                AzureSecurityRealm realm = new AzureSecurityRealm(
                        "tenant", "clientId", Secret.fromString("secret"), 0);
                realm.setUseAppRoles(true);
                realm.setCredentialType("Secret");

                AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                writer = new BinaryStreamWriter(outputStream);
                writer.startNode("parentNode");
                converter.marshal(realm, writer, null);
                writer.endNode();

                byte[] bytes = outputStream.toByteArray();
                reader = new BinaryStreamReader(new ByteArrayInputStream(bytes));
                AzureSecurityRealm result = (AzureSecurityRealm) converter.unmarshal(reader, null);

                assertTrue(result.isUseAppRoles(),
                        "useAppRoles should be true after round-trip");
            } finally {
                if (writer != null) writer.close();
                if (reader != null) reader.close();
            }
        }

        @Test
        @DisplayName("2.2 useAppRoles=false is persisted through marshal/unmarshal")
        void testUseAppRolesFalsePersisted() {
            BinaryStreamWriter writer = null;
            BinaryStreamReader reader = null;
            try {
                AzureSecurityRealm realm = new AzureSecurityRealm(
                        "tenant", "clientId", Secret.fromString("secret"), 0);
                realm.setUseAppRoles(false);
                realm.setCredentialType("Secret");

                AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                writer = new BinaryStreamWriter(outputStream);
                writer.startNode("parentNode");
                converter.marshal(realm, writer, null);
                writer.endNode();

                byte[] bytes = outputStream.toByteArray();
                reader = new BinaryStreamReader(new ByteArrayInputStream(bytes));
                AzureSecurityRealm result = (AzureSecurityRealm) converter.unmarshal(reader, null);

                assertFalse(result.isUseAppRoles(),
                        "useAppRoles should be false after round-trip");
            } finally {
                if (writer != null) writer.close();
                if (reader != null) reader.close();
            }
        }

        @Test
        @DisplayName("2.3 useAppRoles and disableGraphIntegration are independent")
        void testUseAppRolesAndDisableGraphAreIndependent() {
            BinaryStreamWriter writer = null;
            BinaryStreamReader reader = null;
            try {
                AzureSecurityRealm realm = new AzureSecurityRealm(
                        "tenant", "clientId", Secret.fromString("secret"), 0);
                realm.setUseAppRoles(true);
                realm.setDisableGraphIntegration(false);
                realm.setCredentialType("Secret");

                AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                writer = new BinaryStreamWriter(outputStream);
                writer.startNode("parentNode");
                converter.marshal(realm, writer, null);
                writer.endNode();

                byte[] bytes = outputStream.toByteArray();
                reader = new BinaryStreamReader(new ByteArrayInputStream(bytes));
                AzureSecurityRealm result = (AzureSecurityRealm) converter.unmarshal(reader, null);

                assertTrue(result.isUseAppRoles(),
                        "useAppRoles should be true");
                assertFalse(result.isDisableGraphIntegration(),
                        "disableGraphIntegration should be false (independent)");
            } finally {
                if (writer != null) writer.close();
                if (reader != null) reader.close();
            }
        }

        @Test
        @DisplayName("2.4 Legacy config without useAppRoles defaults to false")
        void testLegacyConfigDefaultsToFalse() {
            BinaryStreamWriter writer = null;
            BinaryStreamReader reader = null;
            try {
                // Create a realm WITHOUT setting useAppRoles to simulate legacy config
                AzureSecurityRealm realm = new AzureSecurityRealm(
                        "tenant", "clientId", Secret.fromString("secret"), 0);
                realm.setCredentialType("Secret");
                // Don't call setUseAppRoles — it defaults to false

                AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                writer = new BinaryStreamWriter(outputStream);
                writer.startNode("parentNode");
                converter.marshal(realm, writer, null);
                writer.endNode();

                byte[] bytes = outputStream.toByteArray();
                reader = new BinaryStreamReader(new ByteArrayInputStream(bytes));
                AzureSecurityRealm result = (AzureSecurityRealm) converter.unmarshal(reader, null);

                assertFalse(result.isUseAppRoles(),
                        "useAppRoles should default to false for backward compatibility");
            } finally {
                if (writer != null) writer.close();
                if (reader != null) reader.close();
            }
        }

        @Test
        @DisplayName("2.5 WorkloadIdentity credential type with useAppRoles persists correctly")
        void testWorkloadIdentityWithAppRoles() {
            BinaryStreamWriter writer = null;
            BinaryStreamReader reader = null;
            try {
                AzureSecurityRealm realm = new AzureSecurityRealm(
                        "tenant", "clientId", Secret.fromString(""), 0);
                realm.setCredentialType("WorkloadIdentity");
                realm.setUseAppRoles(true);

                AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                writer = new BinaryStreamWriter(outputStream);
                writer.startNode("parentNode");
                converter.marshal(realm, writer, null);
                writer.endNode();

                byte[] bytes = outputStream.toByteArray();
                reader = new BinaryStreamReader(new ByteArrayInputStream(bytes));
                AzureSecurityRealm result = (AzureSecurityRealm) converter.unmarshal(reader, null);

                assertTrue(result.isUseAppRoles(),
                        "useAppRoles should be true");
                assertEquals("WorkloadIdentity", result.getCredentialType(),
                        "credentialType should be WorkloadIdentity");
            } finally {
                if (writer != null) writer.close();
                if (reader != null) reader.close();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Category 3 — Configuration persistence across restarts (integration)
    // ═══════════════════════════════════════════════════════════════════════

    @Nested
    @WithJenkins
    @DisplayName("3. Configuration Save & Restart")
    class ConfigurationSaveTest {

        private JenkinsRule r;

        @BeforeEach
        void setUp(JenkinsRule r) {
            this.r = r;
        }

        static Object[][] credentialTypes() {
            return new Object[][]{
                    {"Secret"},
                    {"Certificate"},
                    {"WorkloadIdentity"}
            };
        }

        @ParameterizedTest(name = "{index}: credentialType={0}")
        @MethodSource("credentialTypes")
        @DisplayName("3.1 useAppRoles=true survives Jenkins restart")
        void testUseAppRolesSurvivesRestart(String credentialType) throws Throwable {
            AzureSecurityRealm realm = new AzureSecurityRealm(
                    "tenant", "clientId", Secret.fromString("secret"), 3600);
            realm.setCredentialType(credentialType);
            realm.setUseAppRoles(true);
            if ("Certificate".equals(credentialType)) {
                realm.setClientCertificate("testCert");
            }
            r.jenkins.setSecurityRealm(realm);

            AzureSecurityRealm beforeRestart = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertTrue(beforeRestart.isUseAppRoles(),
                    "useAppRoles should be true before restart");

            r.restart();

            AzureSecurityRealm afterRestart = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertNotNull(afterRestart, "Security realm should not be null after restart");
            assertTrue(afterRestart.isUseAppRoles(),
                    "useAppRoles should be true after restart");
            assertEquals(credentialType, afterRestart.getCredentialType(),
                    "credentialType should survive restart");
        }

        @ParameterizedTest(name = "{index}: credentialType={0}")
        @MethodSource("credentialTypes")
        @DisplayName("3.2 useAppRoles=false survives Jenkins restart")
        void testUseAppRolesFalseSurvivesRestart(String credentialType) throws Throwable {
            AzureSecurityRealm realm = new AzureSecurityRealm(
                    "tenant", "clientId", Secret.fromString("secret"), 3600);
            realm.setCredentialType(credentialType);
            realm.setUseAppRoles(false);
            if ("Certificate".equals(credentialType)) {
                realm.setClientCertificate("testCert");
            }
            r.jenkins.setSecurityRealm(realm);

            r.restart();

            AzureSecurityRealm afterRestart = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertNotNull(afterRestart, "Security realm should not be null after restart");
            assertFalse(afterRestart.isUseAppRoles(),
                    "useAppRoles should be false after restart");
        }
    }
}
