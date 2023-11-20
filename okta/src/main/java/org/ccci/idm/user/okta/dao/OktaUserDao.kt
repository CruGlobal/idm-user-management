package org.ccci.idm.user.okta.dao

import com.okta.sdk.client.Client
import com.okta.sdk.resource.ResourceException
import com.okta.sdk.resource.user.EmailStatus
import com.okta.sdk.resource.user.UserBuilder
import com.okta.sdk.resource.user.UserStatus
import org.ccci.idm.user.Group
import org.ccci.idm.user.SearchQuery
import org.ccci.idm.user.User
import org.ccci.idm.user.dao.AbstractUserDao
import org.ccci.idm.user.dao.exception.ExceededMaximumAllowedResultsException
import org.ccci.idm.user.exception.GroupNotFoundException
import org.ccci.idm.user.exception.InvalidPasswordUserException
import org.ccci.idm.user.exception.UserNotFoundException
import org.ccci.idm.user.okta.OktaGroup
import org.ccci.idm.user.okta.dao.exception.OktaDaoException
import org.ccci.idm.user.okta.dao.util.oktaUserId
import org.ccci.idm.user.okta.dao.util.searchUsers
import org.ccci.idm.user.query.Attribute
import org.ccci.idm.user.query.BooleanExpression
import org.ccci.idm.user.query.ComparisonExpression
import org.ccci.idm.user.query.Expression
import org.joda.time.Instant
import java.util.EnumSet
import java.util.concurrent.BlockingQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.stream.Stream

private const val PROFILE_THEKEY_GUID = "theKeyGuid"
private const val PROFILE_RELAY_GUID = "relayGuid"
private const val PROFILE_EMAIL = "email"
private const val PROFILE_FIRST_NAME = "firstName"
private const val PROFILE_NICK_NAME = "nickName"
private const val PROFILE_LAST_NAME = "lastName"

private const val PROFILE_PHONE_NUMBER = "primaryPhone"
private const val PROFILE_CITY = "city"
private const val PROFILE_STATE = "state"
private const val PROFILE_ZIP_CODE = "zipCode"
private const val PROFILE_COUNTRY = "cruCountryCode"

private const val PROFILE_US_EMPLOYEE_ID = "usEmployeeId"
private const val PROFILE_US_DESIGNATION = "usDesignationNumber"

private const val PROFILE_ORGANIZATION = "organization"
private const val PROFILE_DIVISION = "division"
private const val PROFILE_DEPARTMENT = "department"
private const val PROFILE_MANAGER_ID = "managerId"

private const val PROFILE_ORIGINAL_EMAIL = "original_email"
private const val PROFILE_EMAIL_ALIASES = "emailAliases"

private const val PROFILE_GR_MASTER_PERSON_ID = "grMasterPersonId"
private const val PROFILE_GR_PERSON_ID = "thekeyGrPersonId"

private const val PROFILE_ORCA = "orca"

private val DEFAULT_ATTRS = arrayOf(User.Attr.EMAIL, User.Attr.NAME, User.Attr.FLAGS)
private const val DEACTIVATED_PREFIX = "\$GUID-"
private const val DEACTIVATED_SUFFIX = "@deactivated.cru.org"
private const val DEACTIVATED_LEGACY = "\$GUID$-="

class OktaUserDao(private val okta: Client, private val listeners: List<Listener>? = null) : AbstractUserDao() {
    var maxSearchResults = SEARCH_NO_LIMIT
    var initialGroups: Set<String> = emptySet()
    var loadGroups = true

    private fun findOktaUser(user: User) =
        findOktaUserByOktaUserId(user.oktaUserId) ?: findOktaUserByTheKeyGuid(user.theKeyGuid)

    fun findByOktaUserId(id: String?) = findOktaUserByOktaUserId(id)?.asIdmUser()
    private fun findOktaUserByOktaUserId(id: String?) = id?.let { okta.getUser(id) }

    override fun findByEmail(email: String?, includeDeactivated: Boolean) = when {
        email == null -> null
        includeDeactivated ->
            okta.searchUsers("""profile.$PROFILE_EMAIL eq "$email" or profile.$PROFILE_ORIGINAL_EMAIL eq "$email"""")
        else -> okta.searchUsers("""profile.$PROFILE_EMAIL eq "$email"""")
    }?.firstOrNull()?.asIdmUser()

    override fun findByTheKeyGuid(guid: String?, includeDeactivated: Boolean) =
        findOktaUserByTheKeyGuid(guid)?.asIdmUser()?.takeIf { !it.isDeactivated || includeDeactivated }
    private fun findOktaUserByTheKeyGuid(guid: String?) =
        guid?.let { okta.searchUsers("profile.$PROFILE_THEKEY_GUID eq \"$guid\"").firstOrNull() }

    override fun findByRelayGuid(guid: String?, includeDeactivated: Boolean) =
        guid?.let { okta.searchUsers("profile.$PROFILE_RELAY_GUID eq \"$guid\"").firstOrNull()?.asIdmUser() }
            ?.takeIf { !it.isDeactivated || includeDeactivated }

    // region Stream Users
    override fun streamUsers(
        expression: Expression?,
        includeDeactivated: Boolean,
        restrictMaxAllowed: Boolean
    ): Stream<User> {
        val search = expression?.toOktaExpression(includeDeactivated)
        return okta.listUsers(null, null, null, search, null).stream()
            .map { it.asIdmUser(loadGroups = false) }
            .filter { !it.isDeactivated || includeDeactivated }
            .restrictMaxAllowed(restrictMaxAllowed)
    }

    override fun streamUsersInGroup(
        group: Group,
        expression: Expression?,
        includeDeactivated: Boolean,
        restrictMaxAllowed: Boolean
    ): Stream<User> {
        require(group is OktaGroup) { "OktaGroup is required for streamUsersInGroup" }
        val oktaGroup = group.id?.let { okta.getGroup(it) } ?: throw GroupNotFoundException()

        return oktaGroup.listUsers().stream()
            .map { it.asIdmUser(loadGroups = false) }
            .filter { !it.isDeactivated || includeDeactivated }
            .filter { expression?.matches(it) != false }
            .restrictMaxAllowed(restrictMaxAllowed)
    }

    private fun <T> Stream<T>.restrictMaxAllowed(restrict: Boolean = true) =
        if (restrict && maxSearchResults != SEARCH_NO_LIMIT) {
            val count = AtomicInteger(0)
            peek {
                if (count.incrementAndGet() > maxSearchResults)
                    throw ExceededMaximumAllowedResultsException("Search exceeded $maxSearchResults results")
            }
        } else this
    // endregion Stream Users

    // region CRUD methods
    override fun save(user: User) {
        assertWritable()
        assertValidUser(user)

        val builder = UserBuilder.instance()
            .putProfileProperty(PROFILE_THEKEY_GUID, user.theKeyGuid)
            .putProfileProperty(PROFILE_RELAY_GUID, user.relayGuid)
            .setEmail(user.email)
            .setPassword(user.password.toCharArray())
            .setFirstName(user.firstName)
            .putProfileProperty(PROFILE_NICK_NAME, user.rawPreferredName)
            .setLastName(user.lastName)
            .putProfileProperty(PROFILE_US_EMPLOYEE_ID, user.employeeId)
            .putProfileProperty(PROFILE_US_DESIGNATION, user.cruDesignation)
            .putProfileProperty(PROFILE_PHONE_NUMBER, user.telephoneNumber)
            .putProfileProperty(PROFILE_EMAIL_ALIASES, user.cruProxyAddresses.toList())
            .putProfileProperty(PROFILE_ORCA, user.isOrca)
            .setGroups(initialGroups)

            // Location profile attributes
            .putProfileProperty(PROFILE_CITY, user.city)
            .putProfileProperty(PROFILE_STATE, user.state)
            .putProfileProperty(PROFILE_ZIP_CODE, user.postal)
            .putProfileProperty(PROFILE_COUNTRY, user.country)

            // HR profile attributes
            .putProfileProperty(PROFILE_ORGANIZATION, user.cruMinistryCode)
            .putProfileProperty(PROFILE_DIVISION, user.cruSubMinistryCode)
            .putProfileProperty(PROFILE_DEPARTMENT, user.departmentNumber)
            .putProfileProperty(PROFILE_MANAGER_ID, user.cruManagerID)

        try {
            builder.buildAndCreate(okta)
                .also { user.oktaUserId = it.id }
        } catch (e: ResourceException) {
            throw e.asIdmException(checkPasswordException = true)
        }

        listeners?.onEach { it.onUserCreated(user) }
    }

    override fun update(user: User, vararg attrs: User.Attr) {
        assertWritable()
        assertValidUser(user)

        // only update Okta if we are updating attributes tracked in Okta
        val attrsSet = EnumSet.noneOf(User.Attr::class.java).apply { addAll(attrs.ifEmpty { DEFAULT_ATTRS }) }
        if (
            attrsSet.contains(User.Attr.EMAIL) || attrsSet.contains(User.Attr.PASSWORD) ||
            attrsSet.contains(User.Attr.NAME) || attrsSet.contains(User.Attr.CRU_PREFERRED_NAME) ||
            attrsSet.contains(User.Attr.CONTACT) || attrsSet.contains(User.Attr.LOCATION) ||
            attrsSet.contains(User.Attr.EMPLOYEE_NUMBER) || attrsSet.contains(User.Attr.CRU_DESIGNATION) ||
            attrsSet.contains(User.Attr.HUMAN_RESOURCE) || attrsSet.contains(User.Attr.CRU_PROXY_ADDRESSES)
        ) {
            val oktaUser = findOktaUser(user) ?: throw UserNotFoundException()

            var changed = false
            attrsSet.forEach {
                when (it) {
                    User.Attr.EMAIL -> {
                        if (user.isDeactivated) {
                            oktaUser.profile.email = "$DEACTIVATED_PREFIX${user.theKeyGuid}$DEACTIVATED_SUFFIX"
                            oktaUser.profile[PROFILE_ORIGINAL_EMAIL] = user.email
                        } else {
                            oktaUser.profile.email = user.email
                            oktaUser.profile[PROFILE_ORIGINAL_EMAIL] = null
                        }
                        oktaUser.profile.login = oktaUser.profile.email
                        changed = true
                    }
                    User.Attr.PASSWORD -> {
                        oktaUser.credentials.password.value = user.password.toCharArray()
                        changed = true
                    }
                    User.Attr.NAME -> {
                        oktaUser.profile.firstName = user.firstName
                        oktaUser.profile[PROFILE_NICK_NAME] = user.rawPreferredName
                        oktaUser.profile.lastName = user.lastName
                        changed = true
                    }
                    User.Attr.CRU_PREFERRED_NAME -> {
                        oktaUser.profile[PROFILE_NICK_NAME] = user.rawPreferredName
                        changed = true
                    }
                    User.Attr.CONTACT -> {
                        oktaUser.profile[PROFILE_PHONE_NUMBER] = user.telephoneNumber
                        changed = true
                    }
                    User.Attr.LOCATION -> {
                        oktaUser.profile[PROFILE_CITY] = user.city
                        oktaUser.profile[PROFILE_STATE] = user.state
                        oktaUser.profile[PROFILE_ZIP_CODE] = user.postal
                        oktaUser.profile[PROFILE_COUNTRY] = user.country
                        changed = true
                    }
                    User.Attr.EMPLOYEE_NUMBER -> {
                        oktaUser.profile[PROFILE_US_EMPLOYEE_ID] = user.employeeId
                        changed = true
                    }
                    User.Attr.CRU_DESIGNATION -> {
                        oktaUser.profile[PROFILE_US_DESIGNATION] = user.cruDesignation
                        changed = true
                    }
                    User.Attr.HUMAN_RESOURCE -> {
                        oktaUser.profile[PROFILE_ORGANIZATION] = user.cruMinistryCode
                        oktaUser.profile[PROFILE_DIVISION] = user.cruSubMinistryCode
                        oktaUser.profile[PROFILE_DEPARTMENT] = user.departmentNumber
                        oktaUser.profile[PROFILE_MANAGER_ID] = user.cruManagerID
                        changed = true
                    }
                    User.Attr.CRU_PROXY_ADDRESSES -> {
                        oktaUser.profile[PROFILE_EMAIL_ALIASES] = user.cruProxyAddresses.toList()
                        changed = true
                    }
                    // these attributes are still tracked in LDAP but not in Okta
                    User.Attr.FLAGS,
                    User.Attr.SECURITYQA,
                    User.Attr.SELFSERVICEKEYS,
                    User.Attr.MFA_SECRET,
                    User.Attr.MFA_INTRUDER_DETECTION -> Unit
                    // we don't care about these attributes at all anymore
                    User.Attr.DOMAINSVISITED,
                    User.Attr.FACEBOOK,
                    User.Attr.GLOBALREGISTRY,
                    User.Attr.LOGINTIME -> Unit
                }
            }

            if (changed) {
                try {
                    oktaUser.update()
                } catch (e: ResourceException) {
                    throw e.asIdmException(checkPasswordException = attrsSet.contains(User.Attr.PASSWORD))
                }
            }
        }

        listeners?.onEach { it.onUserUpdated(user, *attrsSet.toTypedArray()) }
    }

    override fun reactivate(user: User) {
        val oktaUser = findOktaUser(user) ?: return
        super.reactivate(user)
        if (oktaUser.status == UserStatus.SUSPENDED) oktaUser.unsuspend()
    }

    override fun deactivate(user: User) {
        // suspend the account before updating attributes
        val oktaUser = findOktaUser(user) ?: return
        when (oktaUser.status) {
            // account is already suspended
            UserStatus.SUSPENDED -> Unit
            // account was created but hasn't been verified yet, Okta doesn't support suspending these accounts
            UserStatus.STAGED, UserStatus.PROVISIONED -> Unit
            else -> oktaUser.suspend()
        }

        // update account to indicate it is deactivated
        super.deactivate(user)

        // de-provision accounts that we couldn't suspend and that were never actually activated
        if (oktaUser.status == UserStatus.STAGED || oktaUser.status == UserStatus.PROVISIONED) oktaUser.deactivate()
    }
    // endregion CRUD methods

    // region Group methods
    override fun getGroup(groupId: String?) = groupId?.let { okta.getGroup(groupId) }?.asIdmGroup()

    override fun getAllGroups(baseSearch: String?) = okta.listGroups(baseSearch, null, null).asSequence()
        .map { it.asIdmGroup() }
        .filter { baseSearch == null || it.isDescendantOfOrEqualTo(baseSearch) }
        .toList()

    override fun addToGroup(user: User, group: Group) {
        require(group is OktaGroup) { "$group is not an Okta Group" }

        val oktaUser = findOktaUser(user) ?: throw UserNotFoundException()
        oktaUser.addToGroup(group.id)
    }

    override fun removeFromGroup(user: User, group: Group) {
        require(group is OktaGroup) { "$group is not an Okta Group" }

        val oktaUserId = user.oktaUserId ?: findOktaUser(user)?.id ?: throw UserNotFoundException()
        okta.getGroup(group.id)?.removeUser(oktaUserId)
    }
    // endregion Group methods

    // region Unsupported Deprecated Methods
    override fun enqueueAll(queue: BlockingQueue<User>, deactivated: Boolean) = throw UnsupportedOperationException()
    override fun findAllByGroup(group: Group, includeDeactivated: Boolean) = throw UnsupportedOperationException()
    override fun findAllByQuery(query: SearchQuery) = throw UnsupportedOperationException()
    // endregion Unsupported Deprecated Methods

    // region Unused methods
    @Deprecated("guids are no longer used and not present within Okta. find users by the key guid instead.")
    override fun findByGuid(guid: String?, includeDeactivated: Boolean) = null
    override fun findByDesignation(designation: String?, includeDeactivated: Boolean) = TODO("not implemented")
    override fun findByEmployeeId(employeeId: String?, includeDeactivated: Boolean) = TODO("not implemented")
    override fun findByFacebookId(id: String?, includeDeactivated: Boolean) = TODO("not implemented")
    // endregion Unused methods

    private fun ResourceException.asIdmException(checkPasswordException: Boolean = false) = when {
        checkPasswordException && code == "E0000001" && error.message == "Api validation failed: password" ->
            InvalidPasswordUserException(causes.firstOrNull()?.summary?.removePrefix("password: "))
        else -> OktaDaoException(this)
    }

    private fun com.okta.sdk.resource.user.User.asIdmUser(loadGroups: Boolean = this@OktaUserDao.loadGroups): User {
        return User().apply {
            oktaUserId = id
            theKeyGuid = profile.getString(PROFILE_THEKEY_GUID)
            relayGuid = profile.getString(PROFILE_RELAY_GUID) ?: theKeyGuid

            val deactivated = profile.email.startsWith(DEACTIVATED_PREFIX) && profile.email.endsWith(DEACTIVATED_SUFFIX)
            val legacyDeactivated = profile.login.startsWith(DEACTIVATED_LEGACY) && !profile.login.contains("@")
            isDeactivated = deactivated || legacyDeactivated
            email = when {
                deactivated -> profile.getString(PROFILE_ORIGINAL_EMAIL)
                legacyDeactivated -> profile.getString(PROFILE_ORIGINAL_EMAIL) ?: profile.email
                else -> profile.email
            }
            isEmailVerified =
                credentials.emails.firstOrNull { email.equals(it.value, true) }?.status == EmailStatus.VERIFIED

            firstName = profile.firstName
            preferredName = profile.getString(PROFILE_NICK_NAME)
            lastName = profile.lastName
            telephoneNumber = profile.getString(PROFILE_PHONE_NUMBER)

            // location profile attributes
            city = profile.getString(PROFILE_CITY)
            state = profile.getString(PROFILE_STATE)
            postal = profile.getString(PROFILE_ZIP_CODE)
            country = profile.getString(PROFILE_COUNTRY)

            // HR profile attributes
            cruMinistryCode = profile.getString(PROFILE_ORGANIZATION)
            cruSubMinistryCode = profile.getString(PROFILE_DIVISION)
            departmentNumber = profile.getString(PROFILE_DEPARTMENT)
            cruManagerID = profile.getString(PROFILE_MANAGER_ID)

            employeeId = profile.getString(PROFILE_US_EMPLOYEE_ID)
            cruDesignation = profile.getString(PROFILE_US_DESIGNATION)
            cruProxyAddresses = profile.getStringList(PROFILE_EMAIL_ALIASES).orEmpty()

            grMasterPersonId = profile.getString(PROFILE_GR_MASTER_PERSON_ID)
            grPersonId = profile.getString(PROFILE_GR_PERSON_ID)

            loginTime = lastLogin?.let { Instant(it.time) }

            if (loadGroups) setGroups(listGroups().map { it.asIdmGroup() })
        }.also { user -> listeners?.onEach { it.onUserLoaded(user) } }
    }

    private fun com.okta.sdk.resource.group.Group.asIdmGroup() =
        OktaGroup(id = id, oktaGroupType = type, name = profile.name)

    interface Listener {
        fun onUserLoaded(user: User) = Unit
        fun onUserCreated(user: User) = Unit
        fun onUserUpdated(user: User, vararg attrs: User.Attr) = Unit
    }
}

// region Search Expression processing
private fun Expression.toOktaExpression(includeDeactivated: Boolean): String = when (this) {
    is BooleanExpression -> toOktaExpression(includeDeactivated)
    is ComparisonExpression -> toOktaExpression(includeDeactivated)
    else -> throw IllegalArgumentException("Unrecognized Expression: $this")
}

private fun BooleanExpression.toOktaExpression(includeDeactivated: Boolean) = when (type) {
    BooleanExpression.Type.AND -> "(${components.joinToString(" and ") { it.toOktaExpression(includeDeactivated) }})"
    BooleanExpression.Type.OR -> "(${components.joinToString(" or ") { it.toOktaExpression(includeDeactivated) }})"
}

private fun ComparisonExpression.toOktaExpression(includeDeactivated: Boolean): String = when {
    attribute == Attribute.GROUP -> TODO("Group search not implemented yet")
    includeDeactivated && attribute == Attribute.EMAIL ->
        "(${oktaComparisonExpression(PROFILE_EMAIL, type, value)} or " +
            "${oktaComparisonExpression(PROFILE_ORIGINAL_EMAIL, type, value)})"
    else -> oktaComparisonExpression(attribute.toOktaProfileAttribute(), type, value)
}

private fun Attribute.toOktaProfileAttribute() = when (this) {
    Attribute.GUID -> PROFILE_THEKEY_GUID
    Attribute.EMAIL -> PROFILE_EMAIL
    Attribute.EMAIL_ALIAS -> PROFILE_EMAIL_ALIASES
    Attribute.FIRST_NAME -> PROFILE_FIRST_NAME
    Attribute.LAST_NAME -> PROFILE_LAST_NAME
    Attribute.US_EMPLOYEE_ID -> PROFILE_US_EMPLOYEE_ID
    Attribute.US_DESIGNATION -> PROFILE_US_DESIGNATION
    Attribute.GROUP -> throw IllegalArgumentException("GROUP isn't an actual attribute")
}

private fun oktaComparisonExpression(attr: String, oper: ComparisonExpression.Type, value: String?) =
    """profile.$attr ${oper.toOktaOper()} "$value""""

private fun ComparisonExpression.Type.toOktaOper() = when (this) {
    ComparisonExpression.Type.EQ -> "eq"
    ComparisonExpression.Type.SW -> "sw"
    ComparisonExpression.Type.LIKE -> throw UnsupportedOperationException("LIKE is unsupported for OktaUserDao")
}
// endregion Search Expression processing
