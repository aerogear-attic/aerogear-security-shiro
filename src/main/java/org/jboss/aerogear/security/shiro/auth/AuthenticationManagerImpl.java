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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.Sha512Hash;
import org.apache.shiro.subject.Subject;
import org.jboss.aerogear.security.auth.AuthenticationManager;
import org.jboss.aerogear.security.auth.SessionId;
import org.jboss.aerogear.security.shiro.model.User;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import java.io.Serializable;

/**
 * A <i>AuthenticationManager</i> implementation executes the basic authentication operations for User
 */
@ApplicationScoped
public class AuthenticationManagerImpl implements AuthenticationManager<User> {

    @Inject
    private Subject subject;

    @SessionId
    @Produces
    private Serializable sessionId;

    /**
     * Logs in the specified User.
     *
     * @param user represents a simple implementation that holds user's credentials.
     * @throws org.jboss.aerogear.security.exception.AeroGearSecurityException
     *          on login failure.
     */
    @Override
    public boolean login(User user, String password) {
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(),
                new Sha512Hash(password).toHex());

        subject.login(token);
        if (subject.isAuthenticated()) {
            sessionId = subject.getSession().getId();
        } else {
            throw new RuntimeException("Authentication failed");
        }

        return true;
    }

    /**
     * Logs out the specified User from the system.
     *
     * @throws org.jboss.aerogear.security.exception.AeroGearSecurityException
     *          on logout failure.
     */
    @Override
    public void logout() {
        subject.logout();
    }
}
