package org.ccci.idm.user.ldaptive.dao;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeNotNull;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.ccci.idm.user.Group;
import org.ccci.idm.user.User;
import org.ccci.idm.user.dao.exception.ExceededMaximumAllowedResultsException;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.inject.Inject;
import javax.inject.Named;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"ldap.xml", "config.xml", "dao-default.xml"})
public class LdaptiveUserDaoIT {
    private static final Random RAND = new SecureRandom();

    @Inject
    private LdaptiveUserDao dao;

    @Inject
    @Named("group1")
    private Group group1;
    @Inject
    @Named("group2")
    private Group group2;

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
    @Value("${ldap.dn.group:#{null}}")
    private String groupDn = null;

    private void assumeConfigured() throws Exception {
        assumeNotNull(url, base, username, password, dn);
        assumeNotNull(dao);
    }

    private void assumeGroupsConfigured() throws Exception {
        assumeNotNull(groupDn);
        assumeNotNull(group1, group2);
        assumeFalse(group1.equals(group2));
    }

    @Test
    public void testCreateUser() throws Exception {
        assumeConfigured();

        final User user = getUser();

        this.dao.save(user);
    }

    @Test
    public void testFindUser() throws Exception {
        assumeConfigured();

        final User user = getUser();

        this.dao.save(user);

        final User foundUser = this.dao.findByEmail(user.getEmail(), false);

        Assert.assertTrue(user.equals(foundUser));
    }

    @Test
    public void testUpdateUser() throws Exception {
        assumeConfigured();

        User user = getUser();

        this.dao.save(user);

        user.setFirstName(user.getFirstName() + "modified");

        this.dao.update(user, User.Attr.NAME);

        final User foundUser = this.dao.findByEmail(user.getEmail(), false);

        Assert.assertTrue(user.equals(foundUser));
    }

    @Test
    public void testLoginDate() throws Exception {
        assumeConfigured();

        final User user = getUser();
        final String guid = user.getGuid();
        user.setLoginTime(new DateTime().minusDays(30).secondOfMinute().roundFloorCopy());
        this.dao.save(user);

        // see if we load the same value from ldap
        final User saved1 = this.dao.findByGuid(guid, true);
        assertTrue(saved1.getLoginTime().isEqual(user.getLoginTime()));

        // update the login time to now
        saved1.setLoginTime(new DateTime().secondOfMinute().roundFloorCopy());
        this.dao.update(saved1, User.Attr.LOGINTIME);

        // check to see if the update succeeded
        final User saved2 = this.dao.findByGuid(guid, true);
        assertTrue(saved2.getLoginTime().isEqual(saved1.getLoginTime()));
        assertFalse(saved2.getLoginTime().isEqual(user.getLoginTime()));
    }

    @Test
    public void testDeactivatedFiltering() throws Exception {
        assumeConfigured();

        // create a base user
        final User user1 = getStaffUser();
        user1.setFirstName("first_" +RAND.nextInt(Integer.MAX_VALUE));
        user1.setLastName("last_" +RAND.nextInt(Integer.MAX_VALUE));

        // create a duplicate deactivated user
        final User user2 = getStaffUser();
        user2.setEmail(user1.getEmail());
        user2.setFirstName(user1.getFirstName());
        user2.setLastName(user1.getLastName());
        user2.setDeactivated(true);

        // save both users
        this.dao.save(user1);
        this.dao.save(user2);

        // test findAllByFirstName
        {
            final List<User> active = this.dao.findAllByFirstName(user1.getFirstName(), false);
            final List<User> all = this.dao.findAllByFirstName(user1.getFirstName(), true);

            assertEquals(1, active.size());
            assertEquals(2, all.size());

            assertTrue(active.contains(user1));
            assertFalse(active.contains(user2));
            assertTrue(all.contains(user1));
            assertTrue(all.contains(user2));
        }

        // test findAllByLastName
        {
            final List<User> active = this.dao.findAllByLastName(user1.getLastName(), false);
            final List<User> all = this.dao.findAllByLastName(user1.getLastName(), true);

            assertEquals(1, active.size());
            assertEquals(2, all.size());

            assertTrue(active.contains(user1));
            assertFalse(active.contains(user2));
            assertTrue(all.contains(user1));
            assertTrue(all.contains(user2));
        }

        // test findAllByEmail
        {
            final List<User> active = this.dao.findAllByEmail(user1.getEmail(), false);
            final List<User> all = this.dao.findAllByEmail(user1.getEmail(), true);

            assertEquals(1, active.size());
            assertEquals(2, all.size());

            assertTrue(active.contains(user1));
            assertFalse(active.contains(user2));
            assertTrue(all.contains(user1));
            assertTrue(all.contains(user2));
        }

        // create a deactivated user with unique attributes to test individual findBy* support
        final User user3 = getStaffUser();
        user3.setFirstName("first_" +RAND.nextInt(Integer.MAX_VALUE));
        user3.setLastName("last_" +RAND.nextInt(Integer.MAX_VALUE));
        user3.setDeactivated(true);

        // save new user
        this.dao.save(user3);

        // test findByEmail
        {
            final User activeUser = this.dao.findByEmail(user3.getEmail(), false);
            final User anyUser = this.dao.findByEmail(user3.getEmail(), true);

            assertNull(activeUser);
            assertNotNull(anyUser);

            assertEquals(user3, anyUser);
        }
    }

    @Test
    public void testExceededMaximumResults() throws Exception {
        assumeConfigured();

        // create multiple users with the same name and email, one is deactivated
        final User user1 = getStaffUser();
        user1.setFirstName("first_" + RAND.nextInt(Integer.MAX_VALUE));
        user1.setLastName("last_" + RAND.nextInt(Integer.MAX_VALUE));
        final User user2 = getStaffUser();
        user2.setEmail(user1.getEmail());
        user2.setFirstName(user1.getFirstName());
        user2.setLastName(user1.getLastName());
        user2.setDeactivated(true);

        // save both users
        this.dao.save(user1);
        this.dao.save(user2);

        // test no limit
        {
            this.dao.setMaxSearchResults(0);

            final List<User> firstNameUsers = this.dao.findAllByFirstName(user1.getFirstName(), true);
            assertEquals(2, firstNameUsers.size());

            final List<User> lastNameUsers = this.dao.findAllByLastName(user1.getLastName(), true);
            assertEquals(2, lastNameUsers.size());

            final List<User> emailUsers = this.dao.findAllByEmail(user1.getEmail(), true);
            assertEquals(2, emailUsers.size());
        }

        // test with maxSearchResults = 1
        try {
            this.dao.setMaxSearchResults(1);

            // test first name
            try {
                this.dao.findAllByFirstName(user1.getFirstName(), true);
                fail("ExceededMaximumAllowedResultsException was not thrown by findAllByFirstName");
            } catch (final ExceededMaximumAllowedResultsException e) {
                // this exception was expected
            }

            // test last name
            try {
                this.dao.findAllByLastName(user1.getLastName(), true);
                fail("ExceededMaximumAllowedResultsException was not thrown by findAllByLastName");
            } catch (final ExceededMaximumAllowedResultsException e) {
                // this exception was expected
            }

            // test last name
            try {
                this.dao.findAllByEmail(user1.getEmail(), true);
                fail("ExceededMaximumAllowedResultsException was not thrown by findAllByEmail");
            } catch (final ExceededMaximumAllowedResultsException e) {
                // this exception was expected
            }
        } finally {
            // disable limit to prevent interference in other tests
            this.dao.setMaxSearchResults(0);
        }
    }

    @Test
    public void testEnqueueAll() throws Exception {
        assumeConfigured();

        final BlockingQueue<User> queue = new LinkedBlockingQueue<User>(5);
        final AtomicInteger seen = new AtomicInteger(0);
        final User STOP = new User();
        try {
            // increase the max page size to reduce I/O delays
            this.dao.setMaxPageSize(50);

            // start background processing thread
            final Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        while (true) {
                            // quit processing if we encounter the stop user
                            if (queue.take() == STOP) {
                                return;
                            }

                            // increment seen counter
                            seen.incrementAndGet();
                        }
                    } catch (final InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                }
            });
            thread.start();

            // enqueue all users
            final int count = this.dao.enqueueAll(queue, true);

            // stop processing and join thread
            queue.add(STOP);
            thread.join();

            // check final state
            assertTrue("No users were queued, something might be wrong", count > 0);
            assertTrue(queue.isEmpty());
            assertEquals(seen.get(), count);
        } finally {
            // reset maxPageSize to force paging for other tests
            this.dao.setMaxPageSize(1);
        }
    }

    @Test
    public void testCreateStaffUser() throws Exception {
        assumeConfigured();

        final User user = getStaffUser();

        this.dao.save(user);
    }

    @Test
    public void testUpdateStaffUser() throws Exception {
        assumeConfigured();

        final User user = getStaffUser();

        this.dao.save(user);

        User foundUser = this.dao.findByEmail(user.getEmail(), false);

        Assert.assertTrue(user.equals(foundUser));

        user.setCity(user.getCity() + "modified");
        user.setEmployeeId(user.getEmployeeId() + "modified");

        this.dao.update(user, User.Attr.LOCATION, User.Attr.EMPLOYEE_NUMBER);

        foundUser = this.dao.findByEmail(user.getEmail(), false);

        Assert.assertTrue(user.equals(foundUser));
    }

    @Test
    public void testFindUserByEmployeeId() throws Exception {
        assumeConfigured();

        final User user = getStaffUser();

        this.dao.save(user);

        final User foundUser = this.dao.findByEmployeeId(user.getEmployeeId(), false);

        Assert.assertNotNull(foundUser);

        Assert.assertTrue(user.equals(foundUser));
    }

    @Test
    public void testAddToGroupAndRemoveFromGroup() throws Exception {
        assumeConfigured();
        assumeGroupsConfigured();

        final User user = getUser();

        this.dao.save(user);

        // test adding this user to group1
        {
            this.dao.addToGroup(user, group1);
            final User foundUser = this.dao.findByEmail(user.getEmail(), false);
            assertEquals(ImmutableSet.of(group1), foundUser.getGroups());
            foundUser.setGroups(null);
            assertEquals(user, foundUser);
        }

        // test adding this user to group2
        {
            this.dao.addToGroup(user, group2);
            final User foundUser = this.dao.findByEmail(user.getEmail(), false);
            assertEquals(ImmutableSet.of(group1, group2), foundUser.getGroups());
            foundUser.setGroups(null);
            assertEquals(user, foundUser);
        }

        // test removing this user from group 1
        {
            this.dao.removeFromGroup(user, group1);
            final User foundUser = this.dao.findByEmail(user.getEmail(), false);
            assertEquals(ImmutableSet.of(group2), foundUser.getGroups());
            foundUser.setGroups(null);
            assertEquals(user, foundUser);
        }

        // test removing this user from group 2
        {
            this.dao.removeFromGroup(user, group2);
            final User foundUser = this.dao.findByEmail(user.getEmail(), false);
            assertEquals(ImmutableSet.of(), foundUser.getGroups());
            assertEquals(user, foundUser);
        }
    }

    private User getUser() {
        final User user = new User();
        user.setEmail("test.user." + RAND.nextInt(Integer.MAX_VALUE) + "@example.com");
        user.setGuid(UUID.randomUUID().toString().toUpperCase());
        user.setFirstName("Test");
        user.setLastName("User");

        return user;
    }

    private User getStaffUser() {
        final User user = getUser();

        user.setEmployeeId("000123457");
        user.setDepartmentNumber("USDSABC");
        user.setCruDesignation("123457");
        user.setCruGender("M");
        user.setCity("Orlando");
        user.setState("FL");
        user.setPostal("32832");
        Collection<String> collection = Sets.newHashSet("smtp:test.user@cru.org", "smtp:test.user@ccci.org");
        user.setCruProxyAddresses(collection);

        return user;
    }
}
