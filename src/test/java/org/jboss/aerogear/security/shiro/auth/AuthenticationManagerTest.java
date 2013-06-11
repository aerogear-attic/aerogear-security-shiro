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

package org.jboss.aerogear.security.shiro.auth;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.jboss.aerogear.security.auth.AuthenticationManager;
import org.jboss.aerogear.security.shiro.model.User;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthenticationManagerTest {

    @Mock
    private User user;
    @Mock
    private Subject subject;
    @Mock
    private Session session;

    @InjectMocks
    private AuthenticationManager authenticationManager = new AuthenticationManagerImpl();

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        when(user.getUsername()).thenReturn("john");
        when(user.getPassword()).thenReturn("123");
        when(session.getId()).thenReturn("test");
        when(subject.getSession()).thenReturn(session);
    }

    @Test
    public void testLogin() throws Exception {
        when(subject.isAuthenticated()).thenReturn(true);
        authenticationManager.login(user, "123");
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidLogin() throws Exception {
        when(subject.isAuthenticated()).thenReturn(false);
        authenticationManager.login(user, "123");
    }

    @Test
    public void testLogout() throws Exception {
        when(subject.isAuthenticated()).thenReturn(true);
        authenticationManager.logout();
        verify(subject).logout();
    }
}
