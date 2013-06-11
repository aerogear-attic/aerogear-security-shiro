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

import org.apache.shiro.crypto.hash.Sha512Hash;
import org.apache.shiro.subject.Subject;
import org.jboss.aerogear.security.auth.LoggedUser;
import org.jboss.aerogear.security.auth.Secret;
import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.otp.api.Base32;
import org.jboss.aerogear.security.shiro.model.User;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@ApplicationScoped
public class IdentityManagementImpl implements IdentityManagement<User> {

    @Inject
    private EntityManager entityManager;

    @Inject
    private GrantConfiguration grantConfiguration;

    @Inject
    private Subject subject;

    @Override
    public GrantMethods grant(String... roles) {
        return grantConfiguration.roles(roles);
    }

    @Override
    public User findByUsername(String username) throws RuntimeException {
        User user = entityManager.createNamedQuery("User.findByUsername", User.class)
                .setParameter("username", username)
                .getSingleResult();
        if (user == null) {
            throw new RuntimeException("AeroGearUser do not exist");
        }
        return user;
    }

    @Override
    public User findById(long id) throws RuntimeException {
        return entityManager.find(User.class, id);
    }

    @Override
    public void remove(String username) {
        User user = entityManager.createNamedQuery("User.findByUsername", User.class)
                .setParameter("username", username)
                .getSingleResult();
        if (user == null) {
            throw new RuntimeException("AeroGearUser do not exist");
        }
        entityManager.remove(user);
    }

    @Override
    public void create(User aeroGearUser, String password) {
        User user = new User(aeroGearUser.getUsername(),
                new Sha512Hash(password).toHex());
        entityManager.persist(user);
    }

    @Produces
    @Secret
    @Override
    public String getSecret() {
        Long id = (Long) subject.getPrincipal();
        User user = entityManager.find(User.class, id);
        if (user.getSecret() == null) {
            user.setSecret(Base32.random());
            entityManager.merge(user);
        }
        return user.getSecret();
    }

    @Produces
    @LoggedUser
    @Override
    public String getLogin() {
        Long id = (Long) subject.getPrincipal();
        User user = entityManager.find(User.class, id);

        return user.getUsername();
    }

    @Override
    public boolean hasRoles(Set<String> roles) {
        return subject.hasAllRoles(roles);
    }

    /**
     * TODO: To be implemented
     */
    @Override
    public List<User> findAllByRole(String roleName) {

        return new ArrayList<User>();
    }
}
