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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Sha512Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.shiro.model.Role;
import org.jboss.aerogear.security.shiro.model.User;

import javax.inject.Inject;

/**
 * Shiro realm configuration
 */
public class SecurityRealm extends AuthorizingRealm {

    @Inject
    private IdentityManagement identityManagerment;

    public SecurityRealm() {
        setName("SecurityRealm");
        setCredentialsMatcher(new HashedCredentialsMatcher(Sha512Hash.ALGORITHM_NAME));
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authToken) throws AuthenticationException {

        UsernamePasswordToken token = (UsernamePasswordToken) authToken;

        User user = (User) identityManagerment.findByUsername(token.getUsername());

        if (user != null) {
            return new SimpleAuthenticationInfo(user.getId(), new Sha512Hash(user.getPassword()), getName());
        } else {
            throw new RuntimeException("Authentication failed");
        }
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        try {
            Long userId = (Long) (principals.fromRealm(getName()).iterator().next());
            User user = (User) identityManagerment.findById(userId);
            if (user != null) {
                SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
                for (Role role : user.getRoles()) {
                    info.addRole(role.getName());
                    info.addStringPermissions(role.getPermissions());
                }
                return info;
            } else {
                throw new RuntimeException("Not authorized");
            }
        } catch (RuntimeException e) {
            throw new RuntimeException("Authorization has failed");
        }
    }

}
