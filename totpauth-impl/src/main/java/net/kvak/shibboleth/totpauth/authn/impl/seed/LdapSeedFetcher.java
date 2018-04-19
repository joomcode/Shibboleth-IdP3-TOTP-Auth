package net.kvak.shibboleth.totpauth.authn.impl.seed;

import net.kvak.shibboleth.totpauth.api.authn.SeedFetcher;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext.AuthState;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.ldap.filter.EqualsFilter;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("deprecation")
public class LdapSeedFetcher implements SeedFetcher {

    /* Class logger */
    private final Logger log = LoggerFactory.getLogger(LdapSeedFetcher.class);

    /* LdapTemplate */
    private LdapTemplate ldapTemplate;

    /* LdapTokenTemplate */
    private LdapTemplate ldapTokenTemplate;

    /* seedToken attribute in ldap */
    private String seedAttribute;

    /* Username attribute in ldap */
    private String userAttribute;

    private String tokenAttribute;

    public void setLdapTemplate(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public void setLdapTokenTemplate(LdapTemplate ldapTokenTemplate) {
        this.ldapTokenTemplate = ldapTokenTemplate;
    }

    public LdapSeedFetcher(String seedAttribute, String userAttribute, String tokenAttribute) {
        log.debug("Construct LdapSeedFetcher with {} - {} - {}", seedAttribute, userAttribute, tokenAttribute);
        this.seedAttribute = seedAttribute;
        this.userAttribute = userAttribute;
        this.tokenAttribute = tokenAttribute;
    }

//	public LdapSeedFetcher(String seedAttribute, String userAttribute) {
//		log.debug("Construct LdapSeedFetcher with {} - {}", seedAttribute, userAttribute);
//		this.seedAttribute = seedAttribute;
//		this.userAttribute = userAttribute;
//	}

    @Override
    public void getSeed(String username, TokenUserContext tokenUserCtx) {
        log.debug("Entering LdapSeedFetcher with user: {}", username);

        try {
            ArrayList<String> list = getAllTokenCodes(username);
            log.debug("seeds list is {}", list.toString());
            if (list.isEmpty() || list.get(0) == null) {
                tokenUserCtx.setState(AuthState.REGISTER);
                log.debug("List with token seeds was empty");
            } else {
                log.debug("Token seed list size is: {} first: {}", list.size(), list.get(0));

                for (String seed : list) {
                    log.debug("Adding seed {} for user {}", seed, username);
                    tokenUserCtx.setTokenSeed(seed);
                }
                tokenUserCtx.setState(AuthState.OK);
            }
        } catch (Exception e) {
            tokenUserCtx.setState(AuthState.MISSING_SEED);
            log.debug("Encountered problems with LDAP", e);
        }

    }

    public ArrayList<String> getAllTokenCodes(String user) {
        log.debug("Entering getAllTokenCodes");
        ArrayList<String> tokenList = new ArrayList<String>();

        try {
            String userDn = fetchDn(user);
            DirContextOperations context = ldapTemplate.lookupContext(userDn);
            String[] values;
            if (tokenAttribute == null) {

                values = context.getStringAttributes(seedAttribute);
            } else {
                log.debug("Token attribute is not null: {}", tokenAttribute);
                String fullUserDn = context.getNameInNamespace();
                log.debug("Full user name is: {}", fullUserDn);
                EqualsFilter tokenFilter = new EqualsFilter(tokenAttribute, fullUserDn);
                log.debug("Filter user name is: {}", fullUserDn);
                log.debug("Trying to find token from ldap with filter {}", tokenFilter.encode());
                List results = ldapTokenTemplate.search(DistinguishedName.EMPTY_PATH, tokenFilter.toString(), new AbstractContextMapper() {
                    protected Object doMapFromContext(DirContextOperations ctx) {
                        log.debug("Found token entry with DN: {}", ctx.getNameInNamespace());
                        byte[] bytes = (byte[]) ctx.getObjectAttribute(seedAttribute);
                        return Base64.encodeBase64String(bytes);
                    }
                });
                values = (String[]) results.toArray(new String[0]);
            }
            if (values.length > 0) {
                for (String value : values) {
                    log.debug("Token value {}", value.trim());
                    tokenList.add(value);
                }
            }


        } catch (Exception e) {
            log.debug("Error with getAllTokenCodes", e);
        }

        return tokenList;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private String fetchDn(String userName) {

        String dn = "";
        EqualsFilter filter = new EqualsFilter(userAttribute, userName);
        log.debug("{} Trying to find user {} dn from ldap with filter", userName, filter.encode());

        List result = ldapTemplate.search(DistinguishedName.EMPTY_PATH, filter.toString(), new AbstractContextMapper() {
            protected Object doMapFromContext(DirContextOperations ctx) {
                return ctx.getDn().toString();
            }
        });
        if (result.size() == 1) {
            log.debug("User {} relative DN is: {}", userName, (String) result.get(0));
            dn = (String) result.get(0);

        } else {
            log.debug("{} User not found or not unique. DN size: {}", result.size());
            throw new RuntimeException("User not found or not unique");
        }

        return dn;
    }

}