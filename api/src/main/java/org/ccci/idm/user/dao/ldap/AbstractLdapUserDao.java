package org.ccci.idm.user.dao.ldap;

import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CHANGEEMAILKEY;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CITY;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_COUNTRY;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_DESIGNATION;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_EMPLOYEE_STATUS;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_GENDER;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_HR_STATUS_CODE;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_JOB_CODE;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_MANAGER_ID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_MINISTRY_CODE;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_PAY_GROUP;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_PREFERRED_NAME;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_PROXY_ADDRESSES;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_CRU_SUB_MINISTRY_CODE;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_DEPARTMENT_NUMBER;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_DOMAINSVISITED;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_EMPLOYEE_NUMBER;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_FACEBOOKID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_FACEBOOKIDSTRENGTH;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_FIRSTNAME;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_LASTNAME;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_LOGINTIME;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_PASSWORD;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_POSTAL_CODE;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_PROPOSEDEMAIL;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_RELAY_GUID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_RESETPASSWORDKEY;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_SIGNUPKEY;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_STATE;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_TELEPHONE;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_ATTR_USERID;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_FLAG_ALLOWPASSWORDCHANGE;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_FLAG_EMAILVERIFIED;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_FLAG_LOGINDISABLED;
import static org.ccci.idm.user.dao.ldap.Constants.LDAP_FLAG_STALEPASSWORD;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.ccci.idm.user.User.Attr;
import org.ccci.idm.user.dao.AbstractUserDao;

import java.util.Map;
import java.util.Set;

public abstract class AbstractLdapUserDao extends AbstractUserDao {

    private static final Map<Attr, Set<String>> MASK = ImmutableMap.<Attr, Set<String>>builder()
            .put(Attr.EMAIL, ImmutableSet.of(LDAP_ATTR_USERID, LDAP_FLAG_EMAILVERIFIED))
            .put(Attr.NAME, ImmutableSet.of(LDAP_ATTR_FIRSTNAME, LDAP_ATTR_LASTNAME))
            .put(Attr.PASSWORD, ImmutableSet.of(LDAP_ATTR_PASSWORD))
            .put(Attr.LOGINTIME, ImmutableSet.of(LDAP_ATTR_LOGINTIME))
            .put(Attr.FLAGS, ImmutableSet.of(LDAP_FLAG_ALLOWPASSWORDCHANGE, LDAP_FLAG_EMAILVERIFIED,
                    LDAP_FLAG_LOGINDISABLED, LDAP_FLAG_STALEPASSWORD))
            .put(Attr.DOMAINSVISITED, ImmutableSet.of(LDAP_ATTR_DOMAINSVISITED))
            .put(Attr.SELFSERVICEKEYS, ImmutableSet.of(LDAP_ATTR_CHANGEEMAILKEY, LDAP_ATTR_PROPOSEDEMAIL,
                    LDAP_ATTR_RESETPASSWORDKEY, LDAP_ATTR_SIGNUPKEY))
            .put(Attr.FACEBOOK, ImmutableSet.of(LDAP_ATTR_FACEBOOKID, LDAP_ATTR_FACEBOOKIDSTRENGTH))
            .put(Attr.RELAY_GUID, ImmutableSet.of(LDAP_ATTR_RELAY_GUID))
            .put(Attr.EMPLOYEE_NUMBER, ImmutableSet.of(LDAP_ATTR_EMPLOYEE_NUMBER))
            .put(Attr.DEPARTMENT_NUMBER, ImmutableSet.of(LDAP_ATTR_DEPARTMENT_NUMBER))
            .put(Attr.CITY, ImmutableSet.of(LDAP_ATTR_CITY))
            .put(Attr.STATE, ImmutableSet.of(LDAP_ATTR_STATE))
            .put(Attr.POSTAL_CODE, ImmutableSet.of(LDAP_ATTR_POSTAL_CODE))
            .put(Attr.COUNTRY, ImmutableSet.of(LDAP_ATTR_COUNTRY))
            .put(Attr.TELEPHONE_NUMBER, ImmutableSet.of(LDAP_ATTR_TELEPHONE))
            .put(Attr.CRU_DESIGNATION, ImmutableSet.of(LDAP_ATTR_CRU_DESIGNATION))
            .put(Attr.CRU_EMPLOYEE_STATUS, ImmutableSet.of(LDAP_ATTR_CRU_EMPLOYEE_STATUS))
            .put(Attr.CRU_GENDER, ImmutableSet.of(LDAP_ATTR_CRU_GENDER))
            .put(Attr.CRU_HR_STATUS_CODE, ImmutableSet.of(LDAP_ATTR_CRU_HR_STATUS_CODE))
            .put(Attr.CRU_JOB_CODE, ImmutableSet.of(LDAP_ATTR_CRU_JOB_CODE))
            .put(Attr.CRU_MANAGER_ID, ImmutableSet.of(LDAP_ATTR_CRU_MANAGER_ID))
            .put(Attr.CRU_MINISTRY_CODE, ImmutableSet.of(LDAP_ATTR_CRU_MINISTRY_CODE))
            .put(Attr.CRU_PAY_GROUP, ImmutableSet.of(LDAP_ATTR_CRU_PAY_GROUP))
            .put(Attr.CRU_PREFERRED_NAME, ImmutableSet.of(LDAP_ATTR_CRU_PREFERRED_NAME))
            .put(Attr.CRU_SUB_MINISTRY_CODE, ImmutableSet.of(LDAP_ATTR_CRU_SUB_MINISTRY_CODE))
            .put(Attr.CRU_PROXY_ADDRESSES, ImmutableSet.of(LDAP_ATTR_CRU_PROXY_ADDRESSES))
            .build();

    private Set<String> MASK_DEFAULT = ImmutableSet.<String>builder().addAll(MASK.get(Attr.EMAIL)).addAll(MASK.get
            (Attr.NAME)).addAll(MASK.get(Attr.FLAGS)).build();

    protected static final int SEARCH_NO_LIMIT = 0;

    protected int maxSearchResults = SEARCH_NO_LIMIT;

    public void setMaxSearchResults(final int limit) {
        this.maxSearchResults = limit;
    }

    protected Set<String> getAttributeMask(final Attr... attrs) {
        // return the default attribute mask
        if (attrs == null || attrs.length == 0) {
            return MASK_DEFAULT;
        }

        // build & return the requested mask
        ImmutableSet.Builder<String> mask = ImmutableSet.builder();
        for(final Attr attr : attrs) {
            mask.addAll(MASK.get(attr));
        }
        return mask.build();
    }
}
