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

import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.shiro.model.Role;
import org.jboss.aerogear.security.shiro.model.User;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import java.util.HashSet;
import java.util.Set;

/**
 * <i>GrantMethods</i> implementation is a builder to apply roles to {@link org.jboss.aerogear.security.model.AeroGearUser}
 */
@ApplicationScoped
public class GrantConfiguration implements IdentityManagement.GrantMethods<User> {

    @Inject
    private EntityManager entityManager;

    private Set<Role> list;

    /**
     * This method specifies which roles will be applied to {@link org.jboss.aerogear.security.model.AeroGearUser}
     *
     * @param roles Array of roles
     * @return builder implementation
     */
    public GrantConfiguration roles(String[] roles) {
        list = new HashSet<Role>();
        for (String name : roles) {
            Role role = entityManager.createNamedQuery("Role.findByName", Role.class)
                    .setParameter("name", name)
                    .getSingleResult();
            list.add(role);
        }
        return this;
    }

    /**
     * This method applies roles specified on {@link org.jboss.aerogear.security.authz.IdentityManagement#grant(String...)}
     *
     * @param aeroGearUser represents a simple user's implementation to hold credentials.
     */
    @Override
    public void to(String username) {

        User user = entityManager.createNamedQuery("User.findByUsername", User.class)
                .setParameter("username", username)
                .getSingleResult();

        user.setRoles(list);
        entityManager.merge(user);

    }
}
