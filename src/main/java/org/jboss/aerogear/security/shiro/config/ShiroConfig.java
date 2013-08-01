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

package org.jboss.aerogear.security.shiro.config;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.jboss.aerogear.security.shiro.authz.SecurityRealm;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.inject.Named;

/**
 * Producer to easily retrieve the Subject into the system
 */
@Singleton
public class ShiroConfig {

    private SecurityManager securityManager;

    @Inject
    private SecurityRealm securityRealm;

    @PostConstruct
    public void init() {
        SecurityManager securityManager = new DefaultSecurityManager(securityRealm);
        SecurityUtils.setSecurityManager(securityManager);
    }

    @Produces
    @Named("securityManager")
    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    @Produces
    public Subject getSubject() {
        return SecurityUtils.getSubject();
    }
}
