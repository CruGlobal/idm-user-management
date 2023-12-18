package org.ccci.idm.user;

import static org.ccci.idm.user.Constants.STRENGTH_FULL;
import static org.ccci.idm.user.Constants.STRENGTH_NONE;

import com.google.common.base.CharMatcher;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Predicates;
import com.google.common.base.Strings;
import com.google.common.collect.Collections2;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.ccci.idm.user.util.HashUtility;
import org.joda.time.ReadableInstant;
import org.springframework.util.StringUtils;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class User implements Cloneable, Serializable {
    private static final long serialVersionUID = -1174980195690210236L;

    public enum Attr {
        EMAIL, PASSWORD, NAME, LOGINTIME, FLAGS, SELFSERVICEKEYS, DOMAINSVISITED, FACEBOOK, GLOBALREGISTRY, LOCATION,
        EMPLOYEE_NUMBER, CRU_DESIGNATION, CONTACT, CRU_PREFERRED_NAME, CRU_PROXY_ADDRESSES, HUMAN_RESOURCE, SECURITYQA,
        MFA_SECRET, MFA_INTRUDER_DETECTION, ORCA
    }

    @Nullable
    private String email;
    private String password;

    @Deprecated
    private String guid;
    private String theKeyGuid;
    private String relayGuid;

    private String firstName;
    private String preferredName;
    private String lastName;

    private ReadableInstant loginTime;
    private ReadableInstant pwdChangedTime;

    // account flags
    private boolean emailVerified = false;
    private boolean allowPasswordChange = true;
    private boolean forcePasswordChange = false;
    private boolean deactivated = false;
    private boolean loginDisabled = false;
    private boolean locked = false;

    // Multi-value attributes
    private final Set<String> domainsVisited = new HashSet<>();
    private final Set<Group> groups = new HashSet<>();

    // self-service verification keys
    private String signupKey = null;
    private String changeEmailKey = null;
    private String resetPasswordKey = null;
    private String proposedEmail = null;

    // mfa properties
    private boolean mfaBypassed = false;
    @Nullable
    private String mfaEncryptedSecret;
    private boolean mfaIntruderLocked = false;
    @Nullable
    private Integer mfaIntruderAttempts;
    @Nullable
    private ReadableInstant mfaIntruderResetTime;

    // federated identities
    private String facebookId = null;
    private double facebookIdStrength = STRENGTH_NONE;

    // Global Registry ID
    @Nullable
    private String grMasterPersonId;
    @Nullable
    private String grStageMasterPersonId;
    @Nullable
    private String grPersonId;
    @Nullable
    private String grStagePersonId;
    @Nullable
    private String grSyncChecksum;
    @Nullable
    private String grStageSyncChecksum;

    // miscellaneous implementation meta-data
    @Nonnull
    private Map<String, Serializable> implMeta = Maps.newHashMap();

    // Cru person attributes
    private String employeeId;
    private String departmentNumber;
    private String cruDesignation;
    private String cruEmployeeStatus;
    private String cruGender;
    private String cruHrStatusCode;
    private String cruJobCode;
    private String cruManagerID;
    private String cruMinistryCode;
    private String cruPayGroup;
    private String cruSubMinistryCode;
    @Nonnull
    private Collection<String> cruProxyAddresses = Sets.newHashSet();
    private boolean orca;

    // other attributes (used by relay)
    private String city;
    private String state;
    private String postal;
    private String country;

    private String telephoneNumber;

    private String securityQuestion;
    private String securityAnswer;

    public User() {
    }

    protected User(final User source) {
        this.email = source.email;
        this.password = source.password;
        this.guid = source.guid;
        this.theKeyGuid = source.theKeyGuid;
        this.relayGuid = source.relayGuid;
        this.firstName = source.firstName;
        preferredName = source.preferredName;
        this.lastName = source.lastName;
        this.emailVerified = source.emailVerified;
        this.allowPasswordChange = source.allowPasswordChange;
        this.forcePasswordChange = source.forcePasswordChange;
        this.deactivated = source.deactivated;
        this.loginDisabled = source.loginDisabled;
        this.locked = source.locked;

        // mfa attributes
        mfaEncryptedSecret = source.mfaEncryptedSecret;
        mfaIntruderLocked = source.mfaIntruderLocked;
        mfaIntruderAttempts = source.mfaIntruderAttempts;
        mfaIntruderResetTime = source.mfaIntruderResetTime;

        this.domainsVisited.addAll(source.domainsVisited);
        this.groups.addAll(source.groups);

        this.signupKey = source.signupKey;
        this.changeEmailKey = source.changeEmailKey;
        this.resetPasswordKey = source.resetPasswordKey;
        this.proposedEmail = source.proposedEmail;

        this.facebookId = source.facebookId;
        this.facebookIdStrength = source.facebookIdStrength;

        grMasterPersonId = source.grMasterPersonId;
        grStageMasterPersonId = source.grStageMasterPersonId;
        grPersonId = source.grPersonId;
        grStagePersonId = source.grStagePersonId;
        grSyncChecksum = source.grSyncChecksum;
        grStageSyncChecksum = source.grStageSyncChecksum;

        this.employeeId = source.employeeId;
        this.departmentNumber = source.departmentNumber;
        this.cruDesignation = source.cruDesignation;
        this.cruEmployeeStatus = source.cruEmployeeStatus;
        this.cruGender = source.cruGender;
        this.cruHrStatusCode = source.cruHrStatusCode;
        this.cruJobCode = source.cruJobCode;
        this.cruManagerID = source.cruManagerID;
        this.cruMinistryCode = source.cruMinistryCode;
        this.cruPayGroup = source.cruPayGroup;
        this.cruSubMinistryCode = source.cruSubMinistryCode;
        this.cruProxyAddresses.addAll(source.cruProxyAddresses);
        this.country = source.country;

        this.city = source.city;
        this.state = source.state;
        this.postal = source.postal;
        this.telephoneNumber = source.telephoneNumber;

        this.implMeta.putAll(source.implMeta);

        this.pwdChangedTime = source.pwdChangedTime;

        this.securityQuestion = source.securityQuestion;
        this.securityAnswer = source.securityAnswer;
    }

    @Nullable
    public String getEmail() {
        return this.email;
    }

    public void setEmail(@Nullable final String email) {
        // preserve the emailVerified flag if the email isn't actually changing
        // (case changes are not considered changing emails)
        final boolean noChange = this.email == null ? email == null : this.email.equalsIgnoreCase(email);
        //noinspection SimplifiableConditionalExpression
        this.setEmail(email, noChange ? this.emailVerified : false);
    }

    public void setEmail(@Nullable final String email, final boolean verified) {
        this.email = email;
        this.emailVerified = verified;
    }

    /**
     * This method is for use by UserDao &amp; UserManager implementations only and is not meant for public use.
     */
    public String getPassword() {
        return this.password;
    }

    public void setPassword(final String password) {
        this.setPassword(password, false);
    }

    public void setPassword(final String password, final boolean forceChange) {
        this.password = password;
        this.forcePasswordChange = forceChange;
    }

    @Deprecated
    public String getGuid() {
        return this.guid;
    }

    @Deprecated
    public void setGuid(final String guid) {
        this.guid = guid;
    }

    public String getTheKeyGuid() {
        return this.theKeyGuid != null ? this.theKeyGuid : this.guid;
    }

    public String getRawTheKeyGuid() {
        return this.theKeyGuid;
    }

    public void setTheKeyGuid(final String guid) {
        this.theKeyGuid = guid;
    }

    public String getRelayGuid() {
        return this.relayGuid != null ? this.relayGuid : this.guid;
    }

    public String getRawRelayGuid() {
        return this.relayGuid;
    }

    public void setRelayGuid(final String guid) {
        this.relayGuid = guid;
    }

    public String getFirstName() {
        return this.firstName;
    }

    public void setFirstName(final String firstName) {
        this.firstName = firstName;
    }

    @Nullable
    public String getRawPreferredName() {
        return preferredName;
    }

    @Nullable
    public String getPreferredName() {
        return !Strings.isNullOrEmpty(preferredName) ? preferredName : firstName;
    }

    public void setPreferredName(@Nullable final String name) {
        preferredName = Objects.equal(firstName, name) ? null : name;
    }

    public String getLastName() {
        return this.lastName;
    }

    public void setLastName(final String lastName) {
        this.lastName = lastName;
    }

    public ReadableInstant getLoginTime()
    {
        return loginTime;
    }

    public void setLoginTime(final ReadableInstant loginTime)
    {
        this.loginTime = loginTime;
    }

    @Nullable
    public ReadableInstant getPasswordChangedTime() {
        return pwdChangedTime;
    }

    public void setPasswordChangedTime(@Nullable final ReadableInstant time) {
        this.pwdChangedTime = time;
    }

    public boolean isEmailVerified() {
        return this.emailVerified;
    }

    public void setEmailVerified(final boolean verified) {
        this.emailVerified = verified;
    }

    public boolean isAllowPasswordChange() {
        return allowPasswordChange;
    }

    public void setAllowPasswordChange(final boolean allow) {
        this.allowPasswordChange = allow;
    }

    public boolean isForcePasswordChange() {
        return forcePasswordChange;
    }

    public void setForcePasswordChange(final boolean force) {
        this.forcePasswordChange = force;
    }

    public boolean isDeactivated() {
        return this.deactivated;
    }

    public void setDeactivated(final boolean deactivated) {
        this.deactivated = deactivated;
    }

    public boolean isLoginDisabled() {
        return this.loginDisabled;
    }

    public void setLoginDisabled(final boolean disabled) {
        this.loginDisabled = disabled;
    }

    public boolean isLocked() {
        return this.locked;
    }

    public void setLocked(final boolean locked) {
        this.locked = locked;
    }

    public String getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(String employeeId) {
        this.employeeId = employeeId;
    }

    public String getDepartmentNumber() {
        return departmentNumber;
    }

    public void setDepartmentNumber(String departmentNumber) {
        this.departmentNumber = departmentNumber;
    }

    public String getCruDesignation() {
        return cruDesignation;
    }

    public void setCruDesignation(String cruDesignation) {
        this.cruDesignation = cruDesignation;
    }

    public String getCruEmployeeStatus() {
        return cruEmployeeStatus;
    }

    public void setCruEmployeeStatus(String cruEmployeeStatus) {
        this.cruEmployeeStatus = cruEmployeeStatus;
    }

    public String getCruGender() {
        return cruGender;
    }

    public void setCruGender(String cruGender) {
        this.cruGender = cruGender;
    }

    public String getCruHrStatusCode() {
        return cruHrStatusCode;
    }

    public void setCruHrStatusCode(String cruHrStatusCode) {
        this.cruHrStatusCode = cruHrStatusCode;
    }

    public String getCruJobCode() {
        return cruJobCode;
    }

    public void setCruJobCode(String cruJobCode) {
        this.cruJobCode = cruJobCode;
    }

    public String getCruManagerID() {
        return cruManagerID;
    }

    public void setCruManagerID(String cruManagerID) {
        this.cruManagerID = cruManagerID;
    }

    public String getCruMinistryCode() {
        return cruMinistryCode;
    }

    public void setCruMinistryCode(String cruMinistryCode) {
        this.cruMinistryCode = cruMinistryCode;
    }

    public String getCruPayGroup() {
        return cruPayGroup;
    }

    public void setCruPayGroup(String cruPayGroup) {
        this.cruPayGroup = cruPayGroup;
    }

    public String getCruSubMinistryCode() {
        return cruSubMinistryCode;
    }

    public void setCruSubMinistryCode(String cruSubMinistryCode) {
        this.cruSubMinistryCode = cruSubMinistryCode;
    }

    @Nonnull
    public Collection<String> getCruProxyAddresses() {
        return cruProxyAddresses;
    }

    public void setCruProxyAddresses(@Nonnull final Collection<String> addresses) {
        cruProxyAddresses = addresses;
    }

    @Deprecated
    public Set<String> getCruPasswordHistory() {
        return Collections.emptySet();
    }

    @Deprecated
    public void setCruPasswordHistory(@Nullable final Collection<String> history) {
    }

    public boolean isOrca() {
        return orca;
    }

    public void setOrca(boolean orca) {
        this.orca = orca;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getPostal() {
        return postal;
    }

    public void setPostal(String postal) {
        this.postal = postal;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getTelephoneNumber() {
        return telephoneNumber;
    }

    public void setTelephoneNumber(String telephoneNumber) {
        this.telephoneNumber = telephoneNumber;
    }

    public String getSecurityQuestion() {
        return securityQuestion;
    }

    public void setSecurityQuestion(final String securityQuestion) {
        this.securityQuestion = securityQuestion;
    }

    /**
     * Not meant for public use.
     */
    public String getSecurityAnswer() {
        return securityAnswer;
    }

    /**
     * Return whether or not this user has a Security Answer set
     *
     * @return boolean indicating if the user has a security answer set
     */
    public boolean hasSecurityAnswer() {
        return !Strings.isNullOrEmpty(securityAnswer);
    }

    /**
     * Check the plain text security answer against this security answer, which is already hashed
     *
     * @param securityAnswer plain text security answer
     *
     * @return true if provided security answer matches this object's
     */
    public boolean checkSecurityAnswer(final String securityAnswer) {
        final String normalized = normalize(securityAnswer);
        return !Strings.isNullOrEmpty(this.securityAnswer) && !Strings.isNullOrEmpty(normalized) &&
                (HashUtility.checkHash(normalized, this.securityAnswer) ||
                        HashUtility.checkHash(securityAnswer, this.securityAnswer));
    }

    /**
     * Store the hashed value of the plain text security answer
     *
     * @param securityAnswer plain text security answer
     */
    public void setSecurityAnswer(final String securityAnswer) {
        this.setSecurityAnswer(securityAnswer, true);
    }

    /**
     * Not meant for public use.
     */
    public void setSecurityAnswer(final String securityAnswer, boolean hash) {
        if (hash) {
            final String normalized = normalize(securityAnswer);
            this.securityAnswer = Strings.isNullOrEmpty(normalized) ? null : HashUtility.getHash(normalized);
        } else {
            this.securityAnswer = securityAnswer;
        }
    }

    private String normalize(final String string) {
        return Strings.isNullOrEmpty(string) ? string :
                CharMatcher.whitespace().trimAndCollapseFrom(string, ' ').toLowerCase();
    }

    /**
     * @return the domainsVisited
     */
    public Set<String> getDomainsVisited() {
        return Collections.unmodifiableSet(this.domainsVisited);
    }

    /**
     * @param domains a collection of domains visited
     */
    public void setDomainsVisited(final Collection<String> domains) {
        this.domainsVisited.clear();
        if (domains != null) {
            this.domainsVisited.addAll(Collections2.filter(domains, Predicates.notNull()));
        }
    }

    public void addDomainsVisited(final String domain) {
        if (StringUtils.hasText(domain)) {
            this.domainsVisited.add(domain);
        }
    }

    /**
     * @param groups the groups to set
     */
    public void setGroups(final Collection<Group> groups) {
        this.groups.clear();
        if (groups != null) {
            this.groups.addAll(groups);
        }
    }

    /**
     * @return the groupMembership
     */
    public Set<Group> getGroups() {
        return Collections.unmodifiableSet(this.groups);
    }

    public String getSignupKey() {
        return this.signupKey;
    }

    public void setSignupKey(final String key) {
        this.signupKey = key;
    }

    public String getChangeEmailKey() {
        return this.changeEmailKey;
    }

    public void setChangeEmailKey(final String key) {
        this.changeEmailKey = key;
    }

    public String getResetPasswordKey() {
        return this.resetPasswordKey;
    }

    public void setResetPasswordKey(final String key) {
        this.resetPasswordKey = key;
    }

    public String getProposedEmail() {
        return this.proposedEmail;
    }

    public void setProposedEmail(final String email) {
        this.proposedEmail = email;
    }

    // region MFA related methods

    public boolean isMfaEnabled() {
        return mfaEncryptedSecret != null;
    }

    public boolean isMfaBypassed() {
        return mfaBypassed;
    }

    public void setMfaBypassed(final boolean bypassed) {
        mfaBypassed = bypassed;
    }

    @Nullable
    public String getMfaEncryptedSecret() {
        return mfaEncryptedSecret;
    }

    public void setMfaEncryptedSecret(@Nullable final String encryptedSecret) {
        mfaEncryptedSecret = encryptedSecret;
    }

    public boolean isMfaIntruderLocked() {
        return mfaIntruderLocked;
    }

    /**
     * @return true if mfaIntruderLocked changed, false if it stayed the same.
     */
    public boolean setMfaIntruderLocked(final boolean state) {
        if (mfaIntruderLocked != state) {
            mfaIntruderLocked = state;
            return true;
        }
        return false;
    }

    @Nullable
    public Integer getMfaIntruderAttempts() {
        return mfaIntruderAttempts;
    }

    /**
     * @return true if mfaIntruderAttempts changed, false if it stayed the same.
     */
    public boolean setMfaIntruderAttempts(@Nullable final Integer attempts) {
        if (!Objects.equal(mfaIntruderAttempts, attempts)) {
            mfaIntruderAttempts = attempts;
            return true;
        }
        return false;
    }

    @Nullable
    public ReadableInstant getMfaIntruderResetTime() {
        return mfaIntruderResetTime;
    }

    /**
     * @return true if mfaIntruderResetTime changed, false if it stayed the same.
     */
    public boolean setMfaIntruderResetTime(@Nullable final ReadableInstant time) {
        if (time == null ? mfaIntruderResetTime != null :
                (mfaIntruderResetTime == null || !time.isEqual(mfaIntruderResetTime))) {
            mfaIntruderResetTime = time;
            return true;
        }
        return false;
    }

    // endregion MFA related methods

    public void setFacebookId(final String id, final Number strength) {
        this.facebookId = id;
        this.facebookIdStrength = (strength != null ? strength.doubleValue() : STRENGTH_NONE);
        if (this.facebookIdStrength < STRENGTH_NONE) {
            this.facebookIdStrength = STRENGTH_NONE;
        } else if (this.facebookIdStrength > STRENGTH_FULL) {
            this.facebookIdStrength = STRENGTH_FULL;
        }
    }

    public String getFacebookId() {
        return this.facebookId;
    }

    public Double getFacebookIdStrengthFor(final String id) {
        if (id != null && id.equals(this.facebookId)) {
            return this.facebookIdStrength;
        }
        return STRENGTH_NONE;
    }

    public void removeFacebookId(final String id) {
        if (id != null && id.equals(this.facebookId)) {
            this.facebookId = null;
            this.facebookIdStrength = STRENGTH_NONE;
        }
    }

    // region Global Registry related methods

    @Nullable
    public String getGrMasterPersonId() {
        return grMasterPersonId;
    }

    public void setGrMasterPersonId(@Nullable final String id) {
        grMasterPersonId = id;
    }

    @Nullable
    public String getGrStageMasterPersonId() {
        return grStageMasterPersonId;
    }

    public void setGrStageMasterPersonId(@Nullable final String id) {
        grStageMasterPersonId = id;
    }

    @Nullable
    public String getGrPersonId() {
        return grPersonId;
    }

    public void setGrPersonId(@Nullable final String id) {
        grPersonId = id;
    }

    @Nullable
    public String getGrStagePersonId() {
        return grStagePersonId;
    }

    public void setGrStagePersonId(@Nullable final String id) {
        grStagePersonId = id;
    }

    @Nullable
    public String getGrSyncChecksum() {
        return grSyncChecksum;
    }

    public void setGrSyncChecksum(@Nullable final String checksum) {
        grSyncChecksum = checksum;
    }

    @Nullable
    public String getGrStageSyncChecksum() {
        return grStageSyncChecksum;
    }

    public void setGrStageSyncChecksum(@Nullable final String checksum) {
        grStageSyncChecksum = checksum;
    }

    // endregion Global Registry related methods

    /**
     * This method is for use by UserDao &amp; UserManager implementations only and is not meant for public use.
     */
    @Nullable
    public <T> T getImplMeta(@Nonnull final String key, @Nonnull final Class<T> clazz) {
        final Serializable obj = this.implMeta.get(key);
        if(clazz.isInstance(obj)) {
            return clazz.cast(obj);
        }
        return null;
    }

    /**
     * This method is for use by UserDao &amp; UserManager implementations only and is not meant for public use.
     */
    public Serializable removeImplMeta(@Nonnull final String key) {
        return this.implMeta.remove(key);
    }

    /**
     * This method is for use by UserDao &amp; UserManager implementations only and is not meant for public use.
     */
    public Serializable setImplMeta(@Nonnull final String key, @Nullable final Serializable obj) {
        return this.implMeta.put(key, obj);
    }

    @Override
    @SuppressWarnings({"CloneDoesntCallSuperClone", "CloneDoesntDeclareCloneNotSupportedException"})
    public User clone() {
        return new User(this);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).omitNullValues()
                .add("email", email)
                .add("guid", guid)
                .add("theKeyGuid", this.getTheKeyGuid())
                .add("relayGuid", this.getRelayGuid())
                .add("firstName", firstName)
                .add("preferredName", preferredName)
                .add("lastName", lastName)
                .add("emailVerified", emailVerified)
                .add("allowPasswordChange", allowPasswordChange)
                .add("forcePasswordChange", forcePasswordChange)
                .add("deactivated", deactivated)
                .add("loginDisabled", loginDisabled)
                .add("locked", locked)
                .add("domainsVisited", domainsVisited)
                .add("groups", groups)
                .add("signupKey", signupKey)
                .add("changeEmailKey", changeEmailKey)
                .add("resetPasswordKey", resetPasswordKey)
                .add("proposedEmail", proposedEmail)
                .add("mfaIntruderLocked", mfaIntruderLocked)
                .add("mfaIntruderAttempts", mfaIntruderAttempts)
                .add("mfaIntruderResetTime", mfaIntruderResetTime)
                .add("facebookId", facebookId)
                .add("facebookIdStrength", facebookIdStrength)
                .add("employeeId", employeeId)
                .add("departmentNumber", departmentNumber)
                .add("cruDesignation", cruDesignation)
                .add("cruEmployeeStatus", cruEmployeeStatus)
                .add("cruGender", cruGender)
                .add("cruHrStatusCode", cruHrStatusCode)
                .add("cruJobCode", cruJobCode)
                .add("cruManagerID", cruManagerID)
                .add("cruMinistryCode", cruMinistryCode)
                .add("cruPayGroup", cruPayGroup)
                .add("cruSubMinistryCode", cruSubMinistryCode)
                .add("cruProxyAddresses", cruProxyAddresses)
                .add("city", city)
                .add("state", state)
                .add("postal", postal)
                .add("country", country)
                .add("telephoneNumber", telephoneNumber)
                .add("pwdChangedTime", pwdChangedTime)
                .add("cruSecurityQuestion", securityQuestion)
                .add("cruSecurityAnswer", securityAnswer)
                .toString();
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(
                email,
                password,
                guid,
                getTheKeyGuid(),
                getRelayGuid(),
                firstName,
                lastName,
                emailVerified,
                allowPasswordChange,
                forcePasswordChange,
                deactivated,
                loginDisabled,
                locked,
                domainsVisited,
                groups,
                signupKey,
                changeEmailKey,
                resetPasswordKey,
                proposedEmail,
                mfaEncryptedSecret,
                mfaIntruderLocked,
                mfaIntruderAttempts,
                mfaIntruderResetTime,
                facebookId,
                facebookIdStrength,
                grMasterPersonId,
                grStageMasterPersonId,
                grPersonId,
                grStagePersonId,
                grSyncChecksum,
                grStageSyncChecksum,
                employeeId,
                departmentNumber,
                cruDesignation,
                cruEmployeeStatus,
                cruGender,
                cruHrStatusCode,
                cruJobCode,
                cruManagerID,
                cruMinistryCode,
                cruPayGroup,
                preferredName,
                cruSubMinistryCode,
                cruProxyAddresses,
                city,
                state,
                postal,
                country,
                telephoneNumber,
                securityQuestion,
                securityAnswer
        );
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {return true;}
        if (obj == null || getClass() != obj.getClass()) {return false;}
        final User other = (User) obj;
        return Objects.equal(this.email, other.email) &&
                Objects.equal(this.password, other.password) &&
                Objects.equal(this.guid, other.guid) &&
                Objects.equal(this.getTheKeyGuid(), other.getTheKeyGuid()) &&
                Objects.equal(this.getRelayGuid(), other.getRelayGuid()) &&
                Objects.equal(this.firstName, other.firstName) &&
                Objects.equal(preferredName, other.preferredName) &&
                Objects.equal(this.lastName, other.lastName) &&
                Objects.equal(this.emailVerified, other.emailVerified) &&
                Objects.equal(this.allowPasswordChange, other.allowPasswordChange) &&
                Objects.equal(this.forcePasswordChange, other.forcePasswordChange) &&
                Objects.equal(this.deactivated, other.deactivated) &&
                Objects.equal(this.loginDisabled, other.loginDisabled) &&
                Objects.equal(this.locked, other.locked) &&
                Objects.equal(this.domainsVisited, other.domainsVisited) &&
                Objects.equal(this.groups, other.groups) &&
                Objects.equal(this.signupKey, other.signupKey) &&
                Objects.equal(this.changeEmailKey, other.changeEmailKey) &&
                Objects.equal(this.resetPasswordKey, other.resetPasswordKey) &&
                Objects.equal(this.proposedEmail, other.proposedEmail) &&
                Objects.equal(mfaEncryptedSecret, other.mfaEncryptedSecret) &&
                mfaIntruderLocked == other.mfaIntruderLocked &&
                Objects.equal(mfaIntruderAttempts, other.mfaIntruderAttempts) &&
                Objects.equal(mfaIntruderResetTime, other.mfaIntruderResetTime) &&
                Objects.equal(this.facebookId, other.facebookId) &&
                Objects.equal(this.facebookIdStrength, other.facebookIdStrength) &&
                Objects.equal(grMasterPersonId, other.grMasterPersonId) &&
                Objects.equal(grStageMasterPersonId, other.grStageMasterPersonId) &&
                Objects.equal(grPersonId, other.grPersonId) &&
                Objects.equal(grStagePersonId, other.grStagePersonId) &&
                Objects.equal(grSyncChecksum, other.grSyncChecksum) &&
                Objects.equal(grStageSyncChecksum, other.grStageSyncChecksum) &&
                Objects.equal(this.employeeId, other.employeeId) &&
                Objects.equal(this.departmentNumber, other.departmentNumber) &&
                Objects.equal(this.cruDesignation, other.cruDesignation) &&
                Objects.equal(this.cruEmployeeStatus, other.cruEmployeeStatus) &&
                Objects.equal(this.cruGender, other.cruGender) &&
                Objects.equal(this.cruHrStatusCode, other.cruHrStatusCode) &&
                Objects.equal(this.cruJobCode, other.cruJobCode) &&
                Objects.equal(this.cruManagerID, other.cruManagerID) &&
                Objects.equal(this.cruMinistryCode, other.cruMinistryCode) &&
                Objects.equal(this.cruPayGroup, other.cruPayGroup) &&
                Objects.equal(this.cruSubMinistryCode, other.cruSubMinistryCode) &&
                this.cruProxyAddresses.size() == other.cruProxyAddresses.size() && this.cruProxyAddresses.containsAll(other.cruProxyAddresses) &&
                Objects.equal(this.city, other.city) &&
                Objects.equal(this.state, other.state) &&
                Objects.equal(this.postal, other.postal) &&
                Objects.equal(this.country, other.country) &&
                Objects.equal(this.telephoneNumber, other.telephoneNumber) &&
                Objects.equal(this.securityQuestion, other.securityQuestion) &&
                Objects.equal(this.securityAnswer, other.securityAnswer);
    }
}
