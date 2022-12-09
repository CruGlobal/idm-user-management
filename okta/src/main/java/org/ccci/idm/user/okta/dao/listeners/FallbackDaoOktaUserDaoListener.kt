package org.ccci.idm.user.okta.dao.listeners

import org.ccci.idm.user.User
import org.ccci.idm.user.dao.UserDao
import org.ccci.idm.user.exception.UserAlreadyExistsException
import org.ccci.idm.user.okta.dao.OktaUserDao

private val UPDATABLE_ATTRS = setOf(
    User.Attr.MFA_SECRET, User.Attr.MFA_INTRUDER_DETECTION,
    User.Attr.SELFSERVICEKEYS,
    User.Attr.SECURITYQA,
    User.Attr.HUMAN_RESOURCE
)

class FallbackDaoOktaUserDaoListener(
    private val dao: UserDao
) : OktaUserDao.Listener {
    override fun onUserLoaded(user: User) {
        dao.findByTheKeyGuid(user.theKeyGuid, true)?.run {
            // MFA attributes
            user.isMfaBypassed = isMfaBypassed
            user.mfaEncryptedSecret = mfaEncryptedSecret
            user.isMfaIntruderLocked = isMfaIntruderLocked
            user.mfaIntruderAttempts = mfaIntruderAttempts
            user.mfaIntruderResetTime = mfaIntruderResetTime

            // self-service keys
            user.signupKey = signupKey
            user.proposedEmail = proposedEmail
            user.changeEmailKey = changeEmailKey
            user.resetPasswordKey = resetPasswordKey

            // SQ & SA
            user.securityQuestion = securityQuestion
            user.setSecurityAnswer(securityAnswer, false)

            // Login Time (fallback if there isn't already a last login time)
            user.loginTime = user.loginTime ?: loginTime

            // HR attributes not stored in Okta but still needed
            user.cruEmployeeStatus = cruEmployeeStatus
        }
    }

    override fun onUserCreated(user: User) {
        try {
            dao.save(user)
        } catch (e: UserAlreadyExistsException) {
            // user already exists, so let's just update the appropriate attributes
            dao.update(user, *UPDATABLE_ATTRS.toTypedArray())
        }
    }

    override fun onUserUpdated(user: User, vararg attrs: User.Attr) {
        val filteredAttrs = attrs.filter { UPDATABLE_ATTRS.contains(it) }
        if (filteredAttrs.isEmpty()) return

        val original = dao.findByTheKeyGuid(user.theKeyGuid, true) ?: return
        dao.update(original, user, *filteredAttrs.toTypedArray())
    }
}
