/*
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.aerogear.security.shiro.authz;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.shiro.model.User;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashSet;
import java.util.Set;

import static junit.framework.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecurityRealmTest {

    @Mock
    private IdentityManagement identityManagement;

    @Mock
    private PrincipalCollection principals;

    @InjectMocks
    private SecurityRealm securityRealm;

    @Before
    public void setUp() throws Exception {
        securityRealm = new SecurityRealm();
        MockitoAnnotations.initMocks(this);
        User user = buildUser();
        when(identityManagement.findByUsername("john")).thenReturn(user);
        when(identityManagement.findById(1L)).thenReturn(user);

        Set<Long> ids = buildPrincipal();
        when(principals.fromRealm("SecurityRealm")).thenReturn(ids);
    }

    private User buildUser() {
        User user = new User("john", "123");
        user.setId(1L);
        return user;
    }

    private Set<Long> buildPrincipal() {
        Set<Long> ids = new HashSet<Long>();
        ids.add(1L);
        return ids;
    }

    @Test
    public void testDoGetAuthenticationInfo() throws Exception {
        UsernamePasswordToken token = new UsernamePasswordToken("john", "123");
        AuthenticationInfo info = securityRealm.doGetAuthenticationInfo(token);
        assertNotNull("User not found", info);
    }

    @Test(expected = RuntimeException.class)
    public void testDoGetAuthenticationInfoInvalidCredentials() throws Exception {
        UsernamePasswordToken token = new UsernamePasswordToken("homer", "123");
        securityRealm.doGetAuthenticationInfo(token);
    }

    @Test
    public void testDoGetAuthorizationInfo() throws Exception {
        AuthorizationInfo info = securityRealm.doGetAuthorizationInfo(principals);
        assertNotNull("User not found", info);
    }

    @Test(expected = RuntimeException.class)
    public void testDoGetAuthorizationInfoInvalidCredential() throws Exception {
        PrincipalCollection invalidPrincipals = mock(PrincipalCollection.class);
        securityRealm.doGetAuthorizationInfo(invalidPrincipals);
    }

}
