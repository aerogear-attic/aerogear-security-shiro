package org.jboss.aerogear.security.shiro.authz;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.crypto.hash.Sha512Hash;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.jboss.aerogear.security.auth.LoggedUser;
import org.jboss.aerogear.security.auth.Secret;
import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.model.AeroGearUser;
import org.jboss.aerogear.security.otp.api.Base32;
import org.jboss.aerogear.security.shiro.model.Role;
import org.jboss.aerogear.security.shiro.model.User;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class IdentityManagementImpl implements IdentityManagement {

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
    public AeroGearUser findByUsername(String username) throws RuntimeException {
        User user = entityManager.createNamedQuery("User.findByUsername", User.class)
                .setParameter("username", username)
                .getSingleResult();
        if (user == null) {
            throw new RuntimeException("AeroGearUser do not exist");
        }
        return user;
    }

    @Override
    public AeroGearUser findById(long id) throws RuntimeException {
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
    public List<AeroGearUser> findAllByRole(String name) {
        Role role = entityManager.createNamedQuery("Role.findByName", Role.class)
                .setParameter("name", name)
                .getSingleResult();
        //TODO
        return new ArrayList<AeroGearUser>();
    }

    @Override
    public void create(AeroGearUser aeroGearUser) {
        User user = new User(aeroGearUser.getUsername(),
                new Sha512Hash(aeroGearUser.getPassword()).toHex());
        entityManager.persist(user);
    }

    @Produces
    @Secret
    public String getSecret() {
        Long id = (Long) subject.getPrincipal();
        User user = entityManager.find(User.class, id);
        if(user.getSecret() == null){
            user.setSecret(Base32.random());
            entityManager.merge(user);
        }
        return user.getSecret();
    }

    @Produces
    @LoggedUser
    public String getLogin() {
        Long id = (Long) subject.getPrincipal();
        User user = entityManager.find(User.class, id);

        return user.getUsername();
    }
}
