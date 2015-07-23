package org.ccci.idm.user;

import static org.ccci.idm.user.TestUtil.guid;
import static org.ccci.idm.user.TestUtil.newUser;
import static org.ccci.idm.user.TestUtil.randomEmail;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNotNull;

import com.google.common.collect.ImmutableList;
import org.ccci.idm.user.DefaultUserManager.SimpleUserManagerListener;
import org.ccci.idm.user.DefaultUserManager.UserManagerListener;
import org.ccci.idm.user.exception.InvalidEmailUserException;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.validation.constraints.NotNull;
import java.security.SecureRandom;
import java.util.Random;

public abstract class AbstractDefaultUserManagerIT {
    protected static final Random RAND = new SecureRandom();

    @Inject
    @NotNull
    protected DefaultUserManager userManager;

    // required config values for tests to pass successfully
    @Value("${ldap.url:#{null}}")
    private String url = null;
    @Value("${ldap.base:#{null}}")
    private String base = null;
    @Value("${ldap.userdn:#{null}}")
    private String username = null;
    @Value("${ldap.password:#{null}}")
    private String password = null;
    @Value("${ldap.dn.user:#{null}}")
    private String dn = null;

    protected void assumeConfigured() throws Exception {
        assumeNotNull(url, base, username, password, dn);
        assumeNotNull(userManager);
    }

    @Test
    public void testCreateUser() throws Exception {
        assumeConfigured();

        // test simple creation
        {
            final User user = newUser();
            this.userManager.createUser(user);
            assertTrue(this.userManager.doesEmailExist(user.getEmail()));
        }

        // test various invalid email addresses
        for (final String email : new String[]{randomEmail() + " ", " " + randomEmail(), "email." + RAND.nextInt
                (Integer.MAX_VALUE)}) {
            final User user = newUser();
            user.setEmail(email);
            try {
                this.userManager.createUser(user);
                fail("no exception for an invalid email");
            } catch(final InvalidEmailUserException expected) {
                // This exception is expected
            }
            assertFalse(this.userManager.doesEmailExist(user.getEmail()));
        }
    }

    @Test
    public void testListeners() throws Exception {
        assumeConfigured();

        // wrap in a try block to reset listeners once we finish
        try {
            final ListenerTestUserManagerListener listener = new ListenerTestUserManagerListener();
            userManager.setListeners(ImmutableList.of(listener));

            // test user creation
            final User user = newUser();
            listener.user = user.clone();
            assertFalse(listener.postCreateCalled);
            userManager.createUser(user);
            assertTrue(listener.postCreateCalled);

            // test user update
            user.setFirstName("abcdefghijklmnopqrstuvwxyzabcdef");
            user.setLastName(guid());
            listener.user = user.clone();
            assertFalse(listener.postUpdateCalled);
            assertFalse(listener.nameUpdated);
            assertFalse(listener.passwordUpdated);
            userManager.updateUser(user, User.Attr.NAME);
            assertTrue(listener.postUpdateCalled);
            assertTrue(listener.nameUpdated);
            assertFalse(listener.passwordUpdated);

            // test deactivation
            listener.user = user.clone();
            assertFalse(listener.postDeactivatedCalled);
            userManager.deactivateUser(user);
            assertTrue(listener.postDeactivatedCalled);

            // test reactivation
            listener.user = user.clone();
            assertFalse(listener.postReactivatedCalled);
            userManager.reactivateUser(user);
            assertTrue(listener.postReactivatedCalled);
        } finally {
            userManager.setListeners(ImmutableList.<UserManagerListener>of());
        }
    }

    private static class ListenerTestUserManagerListener extends SimpleUserManagerListener {
        private User user;
        private boolean postCreateCalled = false;
        private boolean postUpdateCalled = false;
        private boolean postDeactivatedCalled = false;
        private boolean postReactivatedCalled = false;
        private boolean nameUpdated = false;
        private boolean passwordUpdated = false;

        @Override
        public void onPostCreateUser(@Nonnull final User user) {
            super.onPostCreateUser(user);

            assertEquals(this.user.getEmail(), user.getEmail());
            postCreateCalled = true;
        }

        @Override
        public void onPostUpdateUser(@Nonnull final User original, @Nonnull final User user,
                                     @Nonnull final User.Attr... attrs) {
            super.onPostUpdateUser(original, user, attrs);

            assertEquals(this.user.getEmail(), user.getEmail());
            assertEquals(this.user.getFirstName(), user.getFirstName());
            assertEquals(this.user.getLastName(), user.getLastName());
            postUpdateCalled = true;
            for (final User.Attr attr : attrs) {
                switch (attr) {
                    case NAME:
                        nameUpdated = true;
                        break;
                    case PASSWORD:
                        passwordUpdated = true;
                        break;
                    default:
                        fail("unexpected attribute update!");
                }
            }
        }

        @Override
        public void onPostDeactivateUser(@Nonnull final User user) {
            super.onPostDeactivateUser(user);

            assertEquals(this.user.getEmail(), user.getEmail());
            assertTrue(user.isDeactivated());
            postDeactivatedCalled = true;
        }

        @Override
        public void onPostReactivateUser(@Nonnull final User user) {
            super.onPostDeactivateUser(user);

            assertEquals(this.user.getEmail(), user.getEmail());
            assertFalse(user.isDeactivated());
            postReactivatedCalled = true;
        }
    }

    @Test
    public void testUpdateUser() throws Exception {
        assumeConfigured();

        // create base user
        final User user = newUser();
        this.userManager.createUser(user);
        assertTrue(this.userManager.doesEmailExist(user.getEmail()));

        // update email of user
        {
            final String oldEmail = user.getEmail();
            user.setEmail(randomEmail());
            this.userManager.updateUser(user, User.Attr.EMAIL);

            assertFalse(this.userManager.doesEmailExist(oldEmail));
            assertTrue(this.userManager.doesEmailExist(user.getEmail()));
        }

        // update to invalid email
        {
            final String oldEmail = user.getEmail();
            user.setEmail("invalid.email." + RAND.nextInt(Integer.MAX_VALUE));

            try {
                this.userManager.updateUser(user, User.Attr.EMAIL);
                fail("no error when updating to invalid email");
            } catch(final InvalidEmailUserException expected) {
                // This exception is expected
            }

            assertTrue(this.userManager.doesEmailExist(oldEmail));
            assertFalse(this.userManager.doesEmailExist(user.getEmail()));
        }
    }
}
