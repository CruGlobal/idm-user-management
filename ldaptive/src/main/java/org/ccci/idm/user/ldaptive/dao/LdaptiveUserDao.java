package org.ccci.idm.user.ldaptive.dao;

import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CN;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_DESIGNATION;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_EMPLOYEE_NUMBER;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_EQUIVALENT_TO_ME;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_FACEBOOKID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_FIRSTNAME;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_GROUPS;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_GUID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_LASTNAME;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_MEMBER;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_OBJECTCLASS;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_PASSWORDCHANGEDTIME;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_RELAY_GUID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_SECURITY_EQUALS;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_THEKEY_GUID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_USERID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_DEACTIVATED_PREFIX;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_OBJECTCLASS_GROUP_OF_NAMES;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_OBJECTCLASS_PERSON;

import com.google.common.annotations.Beta;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import org.ccci.idm.user.Group;
import org.ccci.idm.user.SearchQuery;
import org.ccci.idm.user.User;
import org.ccci.idm.user.dao.exception.DaoException;
import org.ccci.idm.user.dao.exception.ExceededMaximumAllowedResultsException;
import org.ccci.idm.user.dao.exception.InterruptedDaoException;
import org.ccci.idm.user.dao.ldap.AbstractLdapUserDao;
import org.ccci.idm.user.exception.UserAlreadyExistsException;
import org.ccci.idm.user.ldaptive.Dn;
import org.ccci.idm.user.ldaptive.LdapGroup;
import org.ccci.idm.user.ldaptive.dao.exception.LdaptiveDaoException;
import org.ccci.idm.user.ldaptive.dao.filter.AndFilter;
import org.ccci.idm.user.ldaptive.dao.filter.BaseFilter;
import org.ccci.idm.user.ldaptive.dao.filter.EqualsFilter;
import org.ccci.idm.user.ldaptive.dao.filter.LikeFilter;
import org.ccci.idm.user.ldaptive.dao.filter.NotFilter;
import org.ccci.idm.user.ldaptive.dao.filter.OrFilter;
import org.ccci.idm.user.ldaptive.dao.filter.PresentFilter;
import org.ccci.idm.user.ldaptive.dao.util.DnUtils;
import org.ccci.idm.user.ldaptive.dao.util.LdapUtils;
import org.ccci.idm.user.query.BooleanExpression;
import org.ccci.idm.user.query.ComparisonExpression;
import org.ccci.idm.user.query.Expression;
import org.ccci.idm.user.query.NotExpression;
import org.jetbrains.annotations.Contract;
import org.ldaptive.AddOperation;
import org.ldaptive.AddRequest;
import org.ldaptive.AttributeModification;
import org.ldaptive.AttributeModificationType;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.ModifyDnOperation;
import org.ldaptive.ModifyDnRequest;
import org.ldaptive.ModifyOperation;
import org.ldaptive.ModifyRequest;
import org.ldaptive.Response;
import org.ldaptive.ResultCode;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResult;
import org.ldaptive.beans.LdapEntryMapper;
import org.ldaptive.control.PagedResultsControl;
import org.ldaptive.control.ResponseControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.naming.InterruptedNamingException;
import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class LdaptiveUserDao extends AbstractLdapUserDao {
    private static final Logger LOG = LoggerFactory.getLogger(LdaptiveUserDao.class);

    // common LDAP search filters
    private static final BaseFilter FILTER_PERSON = new EqualsFilter(LDAP_ATTR_OBJECTCLASS, LDAP_OBJECTCLASS_PERSON);
    private static final BaseFilter FILTER_GROUP =
            new EqualsFilter(LDAP_ATTR_OBJECTCLASS, LDAP_OBJECTCLASS_GROUP_OF_NAMES);
    private static final BaseFilter FILTER_DEACTIVATED = new LikeFilter(LDAP_ATTR_CN, LDAP_DEACTIVATED_PREFIX + "*");
    private static final BaseFilter FILTER_NOT_DEACTIVATED = FILTER_DEACTIVATED.not();

    @NotNull
    protected ConnectionFactory connectionFactory;

    @NotNull
    protected LdapEntryMapper<User> userMapper;

    private String baseSearchDn = "";

    @Nullable
    private Dn baseGroupDn = null;

    private int maxPageSize = 1000;

    public void setConnectionFactory(final ConnectionFactory factory) {
        this.connectionFactory = factory;
    }

    public void setUserMapper(final LdapEntryMapper<User> mapper) {
        this.userMapper = mapper;
    }

    public void setBaseSearchDn(final String dn) {
        this.baseSearchDn = dn;
    }

    public void setBaseGroupDn(@Nullable final Dn dn) {
        baseGroupDn = dn;
    }

    public void setBaseGroupDnString(@Nullable final String dn) {
        setBaseGroupDn(dn != null ? DnUtils.toDn(dn) : null);
    }

    public void setMaxPageSize(final int size) {
        this.maxPageSize = size;
    }

    private void assertValidBaseGroupDn() {
        if (baseGroupDn == null) {
            throw new UnsupportedOperationException(
                    "a baseGroupDn needs to be configured before group functionality can be used");
        }
    }

    private void assertValidGroup(@Nonnull final Group group) {
        if (!(group instanceof LdapGroup)) {
            throw new IllegalArgumentException(group + " is not an LDAP group");
        }
        assertValidGroupDn(((LdapGroup) group).getDn());
    }

    private void assertValidGroupDn(@Nonnull final Dn dn) {
        assertValidBaseGroupDn();
        assert baseGroupDn != null;
        if (!dn.isDescendantOfOrEqualTo(baseGroupDn)) {
            throw new IllegalArgumentException(dn + " must be descendant of (or identical to) " + baseGroupDn);
        }
    }

    @Nonnull
    private LdapGroup checkValidGroup(@Nonnull final Group group) {
        assertValidGroup(group);
        return (LdapGroup) group;
    }

    /**
     * find {@link User} objects that match the provided filter. This method should not be considered part of the public
     * API. This is currently exposed publicly as a quick path for advanced search in admin tools.
     *
     * @param filter                    the LDAP search filter to use when searching
     * @param limit                     the maximum number of results to return, a limit of 0 indicates that all results
     *                                  should be returned
     * @param restrictMaxAllowedResults a flag indicating if maxSearchResults should be observed
     * @return
     * @throws ExceededMaximumAllowedResultsException exception thrown when there are more results than the maximum
     */
    @Nonnull
    private List<User> findAllByFilter(@Nullable BaseFilter filter, final boolean includeDeactivated, final int limit,
                                       final boolean restrictMaxAllowedResults)
            throws ExceededMaximumAllowedResultsException {
        try (Stream<User> users = streamUsersByFilter(filter, includeDeactivated, limit, restrictMaxAllowedResults)) {
            return users.collect(Collectors.toList());
        } catch (final ExceededMaximumAllowedResultsException e) {
            // propagate ExceededMaximumAllowedResultsException exceptions
            throw e;
        } catch (final DaoException suppressed) {
            // suppress any other DaoExceptions
            return Collections.emptyList();
        }
    }

    /**
     * @param filter                    the LDAP search filter to use when searching
     * @param includeDeactivated        whether deactivated users should be included with the results
     * @param limit                     the maximum number of results to return, a limit of 0 indicates that all results
     *                                  should be returned
     * @param restrictMaxAllowedResults a flag indicating if maxSearchResults should be observed
     * @return a stream with User's matching the specified filters
     */
    @Nonnull
    private Stream<User> streamUsersByFilter(@Nullable final BaseFilter filter, final boolean includeDeactivated,
                                             final int limit, final boolean restrictMaxAllowedResults) {
        final BaseFilter preparedFilter = prepareUserFilter(filter, includeDeactivated);

        // build search request
        final SearchRequest request = new SearchRequest(baseSearchDn, preparedFilter);
        request.setReturnAttributes("*", LDAP_ATTR_PASSWORDCHANGEDTIME);

        // Stream search request
        Stream<LdapEntry> stream = streamSearchRequest(request, calculatePageSize(limit, restrictMaxAllowedResults));
        if (restrictMaxAllowedResults && maxSearchResults != SEARCH_NO_LIMIT) {
            final AtomicInteger count = new AtomicInteger(0);
            stream = stream.peek(entry -> {
                if (count.incrementAndGet() > maxSearchResults) {
                    LOG.debug("Search exceeds maxSearchResults of {}: Filter: {} Limit: {}", maxSearchResults,
                            preparedFilter.format(), limit);
                    throw new ExceededMaximumAllowedResultsException();
                }
            });
        }
        if (limit != SEARCH_NO_LIMIT) {
            stream = stream.limit(limit);
        }
        return stream.map(e -> {
            final User user = new User();
            userMapper.map(e, user);
            return user;
        });
    }

    private BaseFilter prepareUserFilter(@Nullable BaseFilter filter, final boolean includeDeactivated) {
        filter = filter != null ? filter.and(FILTER_PERSON) : FILTER_PERSON;
        if (!includeDeactivated) {
            filter = filter.and(FILTER_NOT_DEACTIVATED);
        }
        return filter;
    }

    private User findByFilter(final BaseFilter filter, final boolean includeDeactivated) {
        final List<User> results = findAllByFilter(filter, includeDeactivated, 1, false);
        return results.size() > 0 ? results.get(0) : null;
    }

    @Beta
    @Nonnull
    @Override
    @Deprecated
    public List<User> findAllByQuery(@Nonnull final SearchQuery query) throws DaoException {
        // build filter from search query
        final List<BaseFilter> filters = new ArrayList<BaseFilter>();
        if (!Strings.isNullOrEmpty(query.getEmail())) {
            filters.add(new LikeFilter(LDAP_ATTR_USERID, query.getEmail()));
        }
        if (!Strings.isNullOrEmpty(query.getFirstName())) {
            filters.add(new LikeFilter(LDAP_ATTR_FIRSTNAME, query.getFirstName()));
        }
        if (!Strings.isNullOrEmpty(query.getLastName())) {
            filters.add(new LikeFilter(LDAP_ATTR_LASTNAME, query.getLastName()));
        }
        if (!Strings.isNullOrEmpty(query.getEmployeeId())) {
            filters.add(new LikeFilter(LDAP_ATTR_EMPLOYEE_NUMBER, query.getEmployeeId()));
        }
        final Group group = query.getGroup();
        if (group != null) {
            assertValidGroup(group);
            filters.add(new EqualsFilter(LDAP_ATTR_GROUPS, DnUtils.toString((LdapGroup) group)));
        }
        final BaseFilter filter;
        if (filters.size() == 0) {
            filter = null;
        } else if (filters.size() == 1) {
            filter = filters.get(0);
        } else {
            filter = new AndFilter(filters.toArray(new BaseFilter[filters.size()]));
        }

        // execute query
        try (Stream<User> users = streamUsersByFilter(filter, query.isIncludeDeactivated(), SEARCH_NO_LIMIT, true)) {
            return users.collect(Collectors.toList());
        }
    }

    @Override
    @Deprecated
    public User findByGuid(final String guid, final boolean includeDeactivated) {
        return this.findByFilter(new EqualsFilter(LDAP_ATTR_GUID, guid), includeDeactivated);
    }

    @Override
    public User findByRelayGuid(final String guid, final boolean includeDeactivated) {
        // relayGuid == {guid} || (guid == {guid} && relayGuid == null)
        return this.findByFilter(new EqualsFilter(LDAP_ATTR_RELAY_GUID, guid).or(new EqualsFilter(LDAP_ATTR_GUID,
                guid).and(new PresentFilter(LDAP_ATTR_RELAY_GUID).not())), includeDeactivated);
    }

    @Nullable
    @Override
    public User findByTheKeyGuid(final String guid, final boolean includeDeactivated) {
        // theKeyGuid == {guid} || (guid == {guid} && theKeyGuid == null)
        return this.findByFilter(new EqualsFilter(LDAP_ATTR_THEKEY_GUID, guid).or(new EqualsFilter(LDAP_ATTR_GUID,
                guid).and(new PresentFilter(LDAP_ATTR_THEKEY_GUID).not())), includeDeactivated);
    }

    @Override
    public User findByFacebookId(final String id, final boolean includeDeactivated) {
        return this.findByFilter(new EqualsFilter(LDAP_ATTR_FACEBOOKID, id), includeDeactivated);
    }

    @Override
    public User findByEmail(final String email, final boolean includeDeactivated) {
        // filter = (!deactivated && cn = email)
        BaseFilter filter = FILTER_NOT_DEACTIVATED.and(new EqualsFilter(LDAP_ATTR_CN, email));

        // filter = (filter || (deactivated && uid = email))
        if (includeDeactivated) {
            filter = filter.or(FILTER_DEACTIVATED.and(new EqualsFilter(LDAP_ATTR_USERID, email)));
        }

        // Execute search & return results
        return this.findByFilter(filter, includeDeactivated);
    }

    @Nullable
    @Override
    public User findByDesignation(@Nullable final String designation, final boolean includeDeactivated) {
        return findByFilter(new EqualsFilter(LDAP_ATTR_CRU_DESIGNATION, designation), includeDeactivated);
    }

    @Override
    public User findByEmployeeId(final String employeeId, final boolean includeDeactivated) {
        return this.findByFilter(new EqualsFilter(LDAP_ATTR_EMPLOYEE_NUMBER, employeeId), includeDeactivated);
    }

    @Override
    @Deprecated
    public int enqueueAll(@Nonnull final BlockingQueue<User> queue, final boolean includeDeactivated)
            throws DaoException {
        try (Stream<User> users = streamUsersByFilter(null, includeDeactivated, SEARCH_NO_LIMIT, false)) {
            final AtomicInteger processed = new AtomicInteger();
            users.forEach(user -> {
                try {
                    queue.put(user);
                } catch (final InterruptedException e) {
                    LOG.debug("Interrupted adding user to the BlockingQueue, let's propagate the exception", e);
                    throw new InterruptedDaoException(e);
                }
                processed.incrementAndGet();
            });
            return processed.get();
        }
    }

    @Nonnull
    @Override
    public Stream<User> streamUsers(@Nullable final Expression expression, final boolean includeDeactivated,
                                    final boolean restrictMaxAllowed) {
        return streamUsersByFilter(convertExpressionToFilter(expression), includeDeactivated, SEARCH_NO_LIMIT, restrictMaxAllowed);
    }

    @Override
    public void save(@Nonnull final User user) throws DaoException {
        assertWritable();
        assertValidUser(user);

        // attempt saving the user
        Connection conn = null;
        try {
            conn = this.connectionFactory.getConnection();
            conn.open();
            final AddOperation add = new AddOperation(conn);
            final LdapEntry entry = new LdapEntry();
            this.userMapper.map(user, entry);
            add.execute(new AddRequest(userMapper.mapDn(user),
                    entry.getAttributes().stream().filter(a -> a.size() > 0).collect(Collectors.toList())));
        } catch (final LdapException e) {
            throw convertLdapException(e);
        } finally {
            LdapUtils.closeConnection(conn);
        }
    }

    @Override
    public void update(@Nonnull final User user, User.Attr... attrs) throws DaoException {
        assertWritable();
        assertValidUser(user);

        Connection conn = null;
        try {
            conn = this.connectionFactory.getConnection();
            conn.open();
            this.updateInternal(conn, this.userMapper.mapDn(user), user, attrs);
        } catch (final LdapException e) {
            throw convertLdapException(e);
        } finally {
            LdapUtils.closeConnection(conn);
        }
    }

    @Override
    public void update(@Nonnull final User original, @Nonnull final User user, final User.Attr... attrs)
            throws DaoException {
        assertWritable();
        assertValidUser(original);
        assertValidUser(user);

        Connection conn = null;
        try {
            conn = this.connectionFactory.getConnection();
            conn.open();

            final String originalDn = this.userMapper.mapDn(original);
            final String dn;
            if (Arrays.asList(attrs).contains(User.Attr.EMAIL)) {
                // modify the DN if we are updating the user's email and it changed
                dn = this.userMapper.mapDn(user);
                if (!Objects.equal(originalDn, dn)) {
                    new ModifyDnOperation(conn).execute(new ModifyDnRequest(originalDn, dn));
                }
            } else {
                dn = originalDn;
            }

            // update the actual user account
            this.updateInternal(conn, dn, user, attrs);
        } catch (final LdapException e) {
            throw convertLdapException(e);
        } finally {
            LdapUtils.closeConnection(conn);
        }
    }

    @Override
    public void addToGroup(@Nonnull final User user, @Nonnull final Group group, final boolean addSecurity)
            throws DaoException {
        assertWritable();
        assertValidUser(user);
        assertValidGroup(group);

        modifyGroupMembership(AttributeModificationType.ADD, user, (LdapGroup) group, addSecurity);
    }

    @Override
    public void removeFromGroup(@Nonnull final User user, @Nonnull final Group group) throws DaoException {
        assertWritable();
        assertValidUser(user);
        assertValidGroup(group);

        modifyGroupMembership(AttributeModificationType.REMOVE, user, (LdapGroup) group, true);
    }

    @Nullable
    @Override
    public Group getGroup(@Nullable final String id) throws DaoException {
        throw new UnsupportedOperationException("getGroup() is not implemented for the LdaptiveUserDao");
    }

    /**
     * Returns all available groups
     *
     * Note that this method is not particular to a user, but is temporarily made available here until a
     * more suitable framework becomes available for providing group dao.
     *
     * @param baseSearch null value indicates to return all groups
     * @return list of all available groups under base search dn
     */
    @Nonnull
    @Override
    public List<Group> getAllGroups(@Nullable final String baseSearch) throws DaoException {
        final Dn baseSearchDn = baseSearch != null ? DnUtils.toDn(baseSearch) : null;
        assertValidBaseGroupDn();
        if (baseSearchDn != null) {
            assertValidGroupDn(baseSearchDn);
        }

        final List<Group> groups = Lists.newArrayList();
        enqueueGroupsByFilter(groups, null, baseSearchDn, SEARCH_NO_LIMIT, false);
        return groups;
    }

    /**
     * @param groups                    collection to populate with loaded groups
     * @param filter                    the LDAP search filter to use when searching
     * @param baseSearchDn        groups base search dn, null defaults to all groups (this.baseGroupDn)
     * @param limit                     the maximum number of results to return, a limit of 0 indicates that all results
     *                                  should be returned
     * @param restrictMaxAllowedResults a flag indicating if maxSearchResults should be observed
     * @return number of users loaded
     * @throws DaoException
     */
    private int enqueueGroupsByFilter(@Nonnull final Collection<Group> groups, @Nullable BaseFilter filter,
                                      @Nullable final Dn baseSearchDn, final int limit,
                                      final boolean restrictMaxAllowedResults) throws DaoException {
        assertValidBaseGroupDn();
        assert baseGroupDn != null;

        // require provided base dn be descendant of (or identical to) groups base dn, under threat of exception
        final Dn searchDn = MoreObjects.firstNonNull(baseSearchDn, baseGroupDn);
        assertValidGroupDn(searchDn);

        filter = filter != null ? filter.and(FILTER_GROUP) : FILTER_GROUP;

        // perform search
        Connection conn = null;
        try {
            conn = this.connectionFactory.getConnection();
            conn.open();
            SearchOperation search = new SearchOperation(conn);
            final SearchRequest request = new SearchRequest(DnUtils.toString(searchDn), filter);

            // restrict results to the specified page size
            final PagedResultsControl prc =
                    new PagedResultsControl(calculatePageSize(limit, restrictMaxAllowedResults));
            request.setControls(prc);

            // retrieve results
            byte[] cookie = null;
            int processed = 0;
            do {
                // execute request
                prc.setCookie(cookie);
                cookie = null;
                final Response<SearchResult> response = search.execute(request);

                // process response
                final SearchResult result = response.getResult();
                final Iterator<LdapEntry> entries = result.getEntries().iterator();
                while ((limit == SEARCH_NO_LIMIT || processed < limit) && (!restrictMaxAllowedResults ||
                        maxSearchResults == SEARCH_NO_LIMIT || processed < maxSearchResults) && entries.hasNext()) {
                    final Dn dn = DnUtils.toDnSafe(entries.next().getDn());
                    if (dn != null && dn.isDescendantOfOrEqualTo(baseGroupDn) && dn.getComponents().size() > 0) {
                        if (groups instanceof BlockingQueue) {
                            try {
                                ((BlockingQueue<Group>) groups).put(dn.asGroup());
                            } catch (final InterruptedException e) {
                                LOG.debug("Error adding group to the BlockingQueue, let's propagate the exception", e);
                                throw new InterruptedDaoException(e);
                            }
                        } else {
                            groups.add(dn.asGroup());
                        }
                    }
                    processed++;
                }

                // process the PRC in the response
                final ResponseControl ctl = response.getControl(PagedResultsControl.OID);
                if (ctl instanceof PagedResultsControl) {
                    // get cookie for next page of results
                    cookie = ((PagedResultsControl) ctl).getCookie();
                }
            } while (cookie != null && cookie.length > 0);

            // return found groups
            return processed;
        } catch (final LdapException e) {
            LOG.debug("error searching for groups, wrapping & propagating exception", e);
            if (e.getCause() instanceof InterruptedNamingException) {
                throw new InterruptedDaoException(e);
            } else {
                throw new LdaptiveDaoException(e);
            }
        } finally {
            LdapUtils.closeConnection(conn);
        }
    }

    private void modifyGroupMembership(@Nonnull final AttributeModificationType type, @Nonnull final User user,
                                       @Nonnull final LdapGroup group, final boolean updateSecurity) throws DaoException {
        Connection conn = null;
        try {
            conn = this.connectionFactory.getConnection();
            conn.open();

            final String userDn = userMapper.mapDn(user);
            final String groupDn = DnUtils.toString(group);

            // modify user entry
            modifyGroupMembershipEntry(conn, userDn, type, LDAP_ATTR_GROUPS, groupDn);
            if (updateSecurity) {
                modifyGroupMembershipEntry(conn, userDn, type, LDAP_ATTR_SECURITY_EQUALS, groupDn);
            }

            // modify group entry
            modifyGroupMembershipEntry(conn, groupDn, type, LDAP_ATTR_MEMBER, userDn);
            if (updateSecurity) {
                modifyGroupMembershipEntry(conn, groupDn, type, LDAP_ATTR_EQUIVALENT_TO_ME, userDn);
            }
        } catch (final LdapException e) {
            throw convertLdapException(e);
        } finally {
            LdapUtils.closeConnection(conn);
        }
    }

    private boolean modifyGroupMembershipEntry(@Nonnull final Connection conn, @Nonnull final String dn,
                                               @Nonnull final AttributeModificationType type,
                                               @Nonnull final String name, @Nonnull final String value)
            throws LdapException {
        final LdapAttribute attribute = new LdapAttribute(name, value);
        final AttributeModification[] modifications = {new AttributeModification(type, attribute)};
        try {
            new ModifyOperation(conn).execute(new ModifyRequest(dn, modifications));
            return true;
        } catch (final LdapException e) {
            // check to see if we are suppressing this exception
            final ResultCode code = e.getResultCode();
            if (code != null) {
                switch (e.getResultCode()) {
                    case ATTRIBUTE_OR_VALUE_EXISTS:
                        if (type == AttributeModificationType.ADD) {
                            return false;
                        }
                        break;
                    case NO_SUCH_ATTRIBUTE:
                        if (type == AttributeModificationType.REMOVE) {
                            return false;
                        }
                        break;
                }
            }

            // propagate the exception otherwise
            throw e;
        }
    }

    private void updateInternal(final Connection conn, final String dn, final User user,
                                User.Attr... attrs) throws LdapException {
        // generate the list of modifications to make for this account
        final ArrayList<AttributeModification> modifications = new ArrayList<AttributeModification>();

        // update attributes set on the user model
        final LdapEntry entry = new LdapEntry();
        this.userMapper.map(user, entry);
        final Set<String> mask = this.getAttributeMask(attrs);

        for (final LdapAttribute attribute : entry.getAttributes()) {
            if (mask.contains(attribute.getName())) {
                modifications.add(new AttributeModification(AttributeModificationType.REPLACE, attribute));
            }
        }

        // execute the ModifyOperation
        new ModifyOperation(conn).execute(new ModifyRequest(dn, modifications.toArray(new
                AttributeModification[modifications.size()])));
    }

    @Nullable
    @Contract("null -> null; !null -> !null")
    @VisibleForTesting
    BaseFilter convertExpressionToFilter(@Nullable final Expression expression) {
        if (expression == null) {
            return null;
        }

        if (expression instanceof BooleanExpression) {
            return convertBooleanExpressionToFilter((BooleanExpression) expression);
        } else if (expression instanceof NotExpression) {
            return new NotFilter(convertExpressionToFilter(((NotExpression) expression).getComponent()));
        } else if (expression instanceof ComparisonExpression) {
            return convertComparisonExpressionToFilter((ComparisonExpression) expression);
        }

        throw new IllegalArgumentException("Unsupported search expression specified");
    }

    private BaseFilter convertBooleanExpressionToFilter(@Nonnull final BooleanExpression expression) {
        final BaseFilter[] filters = expression.getComponents().stream().map(this::convertExpressionToFilter)
                .toArray(BaseFilter[]::new);
        switch (expression.getType()) {
            case AND:
                return new AndFilter(filters);
            case OR:
                return new OrFilter(filters);
            default:
                throw new UnsupportedOperationException("Unrecognized BooleanExpression type: " + expression.getType());
        }
    }

    private BaseFilter convertComparisonExpressionToFilter(@Nonnull final ComparisonExpression expression) {
        final String attrName = expression.getAttribute().ldapAttr;
        final Group group = expression.getGroup();
        final String value = group != null ? DnUtils.toString(checkValidGroup(group)) : expression.getValue();

        // handle special case comparisons
        switch (expression.getAttribute()) {
            case GUID:
                // attr == {value} || (ccciGuid == {value} && attr == null)
                return new EqualsFilter(attrName, value)
                        .or(new EqualsFilter(LDAP_ATTR_GUID, value).and(new PresentFilter(attrName).not()));
        }

        switch (expression.getType()) {
            case EQ:
                return new EqualsFilter(attrName, value);
            case LIKE:
                return new LikeFilter(attrName, value);
            default:
                throw new UnsupportedOperationException("Unrecognized ComparisonExpression type: " + expression
                        .getType());
        }
    }

    @VisibleForTesting
    int calculatePageSize(final int limit, final boolean restrictMaxAllowedResults) {
        // calculate the page size based on the provided limit, maxPageSize, and maxSearchResults
        int pageSize = maxPageSize;
        if (limit != SEARCH_NO_LIMIT && pageSize > limit) {
            pageSize = limit;
        }
        if (restrictMaxAllowedResults && maxSearchResults != SEARCH_NO_LIMIT && pageSize > maxSearchResults + 1) {
            pageSize = maxSearchResults + 1;
        }
        return pageSize;
    }

    @VisibleForTesting
    Stream<LdapEntry> streamSearchRequest(@Nonnull final SearchRequest request, final int pageSize) {
        // open connection
        Connection conn = null;
        try {
            conn = connectionFactory.getConnection();
            conn.open();
        } catch (LdapException e) {
            LdapUtils.closeConnection(conn);
            throw new LdaptiveDaoException(e);
        }

        // create the iterator and Stream
        final Iterator<LdapEntry> iterator = new SearchRequestIterator(conn, request, pageSize);
        return StreamSupport.stream(Spliterators.spliteratorUnknownSize(iterator, Spliterator.NONNULL), false)
                .onClose(conn::close);
    }

    private DaoException convertLdapException(@Nonnull final LdapException e) {
        if (e.getResultCode() == ResultCode.ENTRY_ALREADY_EXISTS) {
            throw new UserAlreadyExistsException();
        } else {
            throw new LdaptiveDaoException(e);
        }
    }
}
