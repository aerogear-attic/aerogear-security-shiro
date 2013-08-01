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

import org.apache.shiro.subject.Subject;
import org.jboss.aerogear.security.shiro.model.User;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.persistence.EntityManager;

import static junit.framework.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdentityManagementTest {

    @Mock
    private Subject subject;

    @Mock
    private EntityManager entityManager;

    @Mock
    private User user;

    @Mock
    private GrantConfiguration grantConfiguration;

    @InjectMocks
    private IdentityManagementImpl identityManagement;

    @Before
    public void setUp() throws Exception {
        identityManagement = new IdentityManagementImpl();
        MockitoAnnotations.initMocks(this);
        when(subject.getPrincipal()).thenReturn(1L);
        when(entityManager.find(User.class, 1L)).thenReturn(user);
    }

    private User buildUser(String username) {
        User user = mock(User.class);
        when(user.getUsername()).thenReturn(username);
        when(user.getEmail()).thenReturn(username + "@doe.com");
        when(user.getPassword()).thenReturn("123");
        return user;
    }

    @Test
    public void testGrant() throws Exception {
        String role = "ADMIN";
        when(identityManagement.grant(role)).thenReturn(grantConfiguration);
        identityManagement.grant(role).to("john");
    }

    @Test
    public void testGetSecret() throws Exception {
        final String secret = "XXCJVM65LRQXCJ4M";
        when(user.getSecret()).thenReturn(secret);
        assertEquals(secret, identityManagement.getSecret());
    }

    @Test
    public void testGetNewSecret() throws Exception {
        final String secret = "XXCJVM65LRQXCJ4M";
        when(entityManager.find(User.class, 1L)).thenReturn(new User("homer", "123"));
        assertNotSame(secret, identityManagement.getSecret());
        assertNotNull(identityManagement.getSecret());
    }
}
