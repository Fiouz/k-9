package com.fsck.k9.authenticator;

import static android.accounts.AccountManager.ERROR_CODE_BAD_ARGUMENTS;
import static android.accounts.AccountManager.ERROR_CODE_BAD_REQUEST;
import static android.accounts.AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION;
import static android.accounts.AccountManager.KEY_ACCOUNT_NAME;
import static android.accounts.AccountManager.KEY_ACCOUNT_TYPE;
import static android.accounts.AccountManager.KEY_AUTHTOKEN;
import static android.accounts.AccountManager.KEY_BOOLEAN_RESULT;
import static android.accounts.AccountManager.KEY_PASSWORD;
import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;

import com.fsck.k9.K9;
import com.fsck.k9.R;

/**
 * Synchronous backend for {@link AccountAuthenticator}. No UI nor
 * threading/callback logic involved.
 * 
 * <p>
 * Method signatures are inspired from {@link AbstractAccountAuthenticator} with
 * modifications to accommodate with the synchronous nature of this class.
 * Notable modifications are the removal of the
 * {@link AccountAuthenticatorResponse} argument since invocations are expected
 * to be synchronous.
 * </p>
 * 
 * <p>
 * This class requires {@link android.Manifest.permission#AUTHENTICATE_ACCOUNTS
 * AUTHENTICATE_ACCOUNTS} permission.
 * </p>
 * 
 * @author Fiouz
 * @see AbstractAccountAuthenticator
 */
public class AuthenticatorHelper {
    private final String LOG_PREFIX = getClass().getSimpleName() + ": ";

    private final Context mContext;

    private final AccountManager mAccountManager;

    public AuthenticatorHelper(final Context context) {
        mContext = context;
        mAccountManager = AccountManager.get(context);
    }

    /**
     * Adds an account of the specified accountType.
     * 
     * @param accountType
     *            the type of account to add, will never be {@code null}
     * @param authTokenType
     *            the type of auth token to retrieve after adding the account,
     *            may be {@code null}
     * @param requiredFeatures
     *            a String array of authenticator-specific features that the
     *            added account must support, may be {@code null}
     * @param options
     *            a Bundle of authenticator-specific options, may be
     *            {@code null}
     * @return a Bundle result. The result will contain:
     *         <ul>
     *         <li> {@link AccountManager#KEY_ACCOUNT_NAME} and
     *         {@link AccountManager#KEY_ACCOUNT_TYPE} of the account that was
     *         added
     *         </ul>
     * @throws NetworkErrorException
     *             if the authenticator could not honor the request due to a
     *             network error
     * @throws AuthenticatorHelperException
     *             to indicate an error
     * @see AbstractAccountAuthenticator#addAccount(AccountAuthenticatorResponse,
     *      String, String, String[], Bundle)
     */
    public Bundle addAccount(final String accountType, final String authTokenType, final String[] requiredFeatures,
                             final Bundle options) throws NetworkErrorException, AuthenticatorHelperException {
        Log.v(K9.LOG_TAG, LOG_PREFIX + "addAccount");

        if (!AccountAuthenticator.ACCOUNT_TYPE.equals(accountType)) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_ARGUMENTS, "Invalid account type requested: "
                    + accountType);
        }

        if (authTokenType != null && !isValidAuthTokenType(authTokenType)) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_ARGUMENTS, "Unsupported auth token type: "
                    + authTokenType);
        }
        if (options == null) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_REQUEST, "Missing options (username, password, etc.)");
        }
        String uuid;
        if (requiredFeatures == null || requiredFeatures.length != 1
                || (uuid = featureToUuid(requiredFeatures[0])) == null) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_REQUEST, "Missing UUID feature");
        }
        final String accountName = options.getString(KEY_ACCOUNT_NAME);
        if (TextUtils.isEmpty(accountName)) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_ARGUMENTS, "Empty account name");
        }
        final Account account = new Account(accountName, accountType);

        // consider online mode is the default value (although unsupported ATM)
        final boolean onlineMode = options.getBoolean(AuthenticatorConstants.KEY_ONLINE, true);

        if (onlineMode) {
            // online mode

            /*
             * online mode
             * 
             * 1. Use connection parameters from 'options' to perform the actual
             * verification
             * 
             * 2. If verification fails, throw exception
             */

            // unsupported for now
            if (!onlinePasswordCheck(options)) {
                throw new AuthenticatorHelperException(ERROR_CODE_BAD_ARGUMENTS, "Verification failed");
            }
        }

        // online check successful OR we're in offline mode

        final String password = options.getString(KEY_PASSWORD);

        // save the associated UUID into userdata
        final Bundle userdata = new Bundle(1);
        userdata.putString(AuthenticatorConstants.KEY_UUID, uuid);

        mAccountManager.addAccountExplicitly(account, password, userdata);
        // since we don't want caller to explicitly call
        // AccountManager.getPassword(), we store the password as a token
        mAccountManager.setAuthToken(account, AuthenticatorConstants.TOKENTYPE_PASSWORD, password);

        final Bundle result;
        if (authTokenType == null) {
            result = new Bundle();
            result.putString(KEY_ACCOUNT_NAME, accountName);
            result.putString(KEY_ACCOUNT_TYPE, accountType);
        } else {
            result = getAuthToken(account, authTokenType, options);
        }

        return result;
    }

    /**
     * Checks that the user knows the credentials of an account.
     * 
     * @param account
     *            the account whose credentials are to be checked, will never be
     *            {@code null}
     * @param options
     *            a Bundle of authenticator-specific options, may be
     *            {@code null}
     * 
     * @return a Bundle result. The result will contain:
     *         <ul>
     *         <li> {@link AccountManager#KEY_BOOLEAN_RESULT}, <code>true</code>
     *         if the check succeeded, <code>false</code> otherwise</li>
     *         </ul>
     * @throws NetworkErrorException
     *             if the authenticator could not honor the request due to a
     *             network error
     * @throws AuthenticatorHelperException
     *             to indicate an error
     * @see AbstractAccountAuthenticator#confirmCredentials(AccountAuthenticatorResponse,
     *      Account, Bundle)
     */
    public Bundle confirmCredentials(final Account account, final Bundle options) throws NetworkErrorException,
            AuthenticatorHelperException {
        Log.v(K9.LOG_TAG, LOG_PREFIX + "confirmCredentials");

        final boolean confirmed;

        if (options == null) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_REQUEST, "No options specified");
        }

        final boolean onlineMode = options.getBoolean(AuthenticatorConstants.KEY_ONLINE, true);
        if (onlineMode) {
            // online mode

            // XXX an improvement would be to retrieve the actual K-9 account
            // settings using the Android Account userdata so that the caller
            // doesn't have to specify all settings

            confirmed = onlinePasswordCheck(options);
        } else {
            // offline mode, compare the stored password
            final String givenPassword = options.getString(KEY_PASSWORD);
            final String expectedPassword = mAccountManager.getPassword(account);
            // if both passwords are null (can be used to ensure password is
            // unset on the device)
            // or if both password are equals
            confirmed = (givenPassword == null && expectedPassword == null)
                    || (expectedPassword != null && expectedPassword.equals(givenPassword));
        }
        return toBooleanBundle(confirmed);
    }

    /**
     * Update the locally stored credentials for an account.
     * 
     * @param account
     *            the account whose credentials are to be updated, will never be
     *            {@code null}
     * @param authTokenType
     *            the type of auth token to retrieve after updating the
     *            credentials, may be {@code null}
     * @param options
     *            a Bundle of authenticator-specific options, may be
     *            {@code null}
     * @return a Bundle result. The result will contain:
     *         <ul>
     *         <li> {@link AccountManager#KEY_ACCOUNT_NAME} and
     *         {@link AccountManager#KEY_ACCOUNT_TYPE} of the account that was
     *         added
     *         </ul>
     * @throws NetworkErrorException
     *             if the authenticator could not honor the request due to a
     *             network error
     * @throws AuthenticatorHelperException
     *             to indicate an error
     * @see AbstractAccountAuthenticator#updateCredentials(AccountAuthenticatorResponse,
     *      Account, String, Bundle)
     */
    /*
     * XXX There seems to be a bug in the Android framework where
     * AccountManager.updateCredentials() throws an exception when authTokenType
     * is null, consequently, authTokenType is unlikely to be null here unless
     * fixed in Android
     */
    public Bundle updateCredentials(final Account account, final String authTokenType, final Bundle options)
            throws NetworkErrorException, AuthenticatorHelperException {
        Log.v(K9.LOG_TAG, LOG_PREFIX + "updateCredentials");

        if (authTokenType != null && !isValidAuthTokenType(authTokenType)) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_ARGUMENTS, "Unsupported auth token type: "
                    + authTokenType);
        }
        if (options == null) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_REQUEST, "Missing options");
        }
        final String password = options.getString(KEY_PASSWORD);
        // password may be null here

        mAccountManager.setPassword(account, password);
        mAccountManager.setAuthToken(account, AuthenticatorConstants.TOKENTYPE_PASSWORD, password);

        final Bundle result;
        if (authTokenType == null) {
            result = new Bundle(2);
            result.putString(KEY_ACCOUNT_NAME, account.name);
            result.putString(KEY_ACCOUNT_TYPE, account.type);
        } else {
            result = getAuthToken(account, authTokenType, options);
        }

        return result;
    }

    /**
     * Checks if the account supports all the specified authenticator specific
     * features.
     * 
     * @param account
     *            the account to check, will never be {@code null}
     * @param features
     *            an array of features to check, will never be {@code null}
     * @return a Bundle result. The result will contain:
     *         <ul>
     *         <li> {@link AccountManager#KEY_BOOLEAN_RESULT}, <code>true</code>
     *         if the account has all the features, <code>false</code> otherwise
     *         </li>
     *         </ul>
     * @throws NetworkErrorException
     *             if the authenticator could not honor the request due to a
     *             network error
     * @throws AuthenticatorHelperException
     *             to indicate an error
     * @see AbstractAccountAuthenticator#hasFeatures(AccountAuthenticatorResponse,
     *      Account, String[])
     */
    public Bundle hasFeatures(final Account account, final String[] features) throws NetworkErrorException,
            AuthenticatorHelperException {
        Log.v(K9.LOG_TAG, LOG_PREFIX + "hasFeature");

        boolean hasFeature = false;
        if (features.length == 0) {
            // yes, we have at least "no feature"
            return toBooleanBundle(true);
        }
        final String uuidFeature = features[0];
        String expectedUuid;
        if (features.length == 1 && (expectedUuid = featureToUuid(uuidFeature)) != null) {
            final String actualUuid = mAccountManager.getUserData(account, AuthenticatorConstants.KEY_UUID);
            hasFeature = expectedUuid.equals(actualUuid);
        }

        return toBooleanBundle(hasFeature);
    }

    private String featureToUuid(final String feature) {
        if (feature.length() > AuthenticatorConstants.FEATURE_UUID_PREFIX.length()
                && feature.startsWith(AuthenticatorConstants.FEATURE_UUID_PREFIX)) {
            return feature.substring(AuthenticatorConstants.FEATURE_UUID_PREFIX.length());
        }
        return null;
    }

    /**
     * @param authTokenType
     *            Can be {@code null}.
     * @return
     */
    private boolean isValidAuthTokenType(final String authTokenType) {
        return AuthenticatorConstants.TOKENTYPE_PASSWORD.equals(authTokenType);
    }

    /**
     * Gets the authtoken for an account.
     * 
     * @param account
     *            the account whose credentials are to be retrieved, will never
     *            be {@code null}
     * @param authTokenType
     *            the type of auth token to retrieve, will never be {@code null}
     * @param options
     *            a Bundle of authenticator-specific options, may be
     *            {@code null}
     * @return a Bundle result. The result will contain:
     *         <ul>
     *         <li> {@link AccountManager#KEY_ACCOUNT_NAME},
     *         {@link AccountManager#KEY_ACCOUNT_TYPE}, and
     *         {@link AccountManager#KEY_AUTHTOKEN}
     *         </ul>
     * @throws NetworkErrorException
     *             if the authenticator could not honor the request due to a
     *             network error
     * @throws AuthenticatorHelperException
     *             to indicate an error
     * @see AbstractAccountAuthenticator#getAuthToken(AccountAuthenticatorResponse,
     *      Account, String, Bundle)
     */
    public Bundle getAuthToken(final Account account, final String authTokenType, final Bundle options)
            throws NetworkErrorException, AuthenticatorHelperException {
        Log.v(K9.LOG_TAG, LOG_PREFIX + "getAuthToken");

        if (AuthenticatorConstants.TOKENTYPE_PASSWORD.equals(authTokenType)) {
            final String password = mAccountManager.getPassword(account);
            return toAuthTokenBundle(account, password);
        }
        throw new AuthenticatorHelperException(ERROR_CODE_BAD_ARGUMENTS, "Unsupported auth token type: "
                + authTokenType);
    }

    /**
     * Ask the authenticator for a localized label for the given authTokenType.
     * 
     * @param authTokenType
     *            the authTokenType whose label is to be returned, will never be
     *            {@code null}
     * @return the localized label of the auth token type, may be {@code null}
     *         if the type isn't known
     * @see AbstractAccountAuthenticator#getAuthTokenLabel(String)
     */
    public String getAuthTokenLabel(final String authTokenType) {
        if (AuthenticatorConstants.TOKENTYPE_PASSWORD.equals(authTokenType)) {
            return mContext.getString(R.string.authenticator_password);
        }
        return null;
    }

    /**
     * Checks if the removal of this account is allowed.
     * 
     * @param account
     *            the account to check, will never be {@code null}
     * @return a Bundle result. The result will contain:
     *         <ul>
     *         <li> {@link AccountManager#KEY_BOOLEAN_RESULT}, <code>true</code>
     *         if the removal of the account is allowed, <code>false</code>
     *         otherwise
     *         </ul>
     * @throws NetworkErrorException
     *             if the authenticator could not honor the request due to a
     *             network error
     * @throws AuthenticatorHelperException
     *             to indicate an error
     * @see AbstractAccountAuthenticator#getAccountRemovalAllowed(AccountAuthenticatorResponse,
     *      Account)
     */
    public Bundle getAccountRemovalAllowed(final Account account) throws NetworkErrorException,
            AuthenticatorHelperException {
        // for now, allow any account removal
        return toBooleanBundle(true);
    }

    private Bundle toBooleanBundle(final boolean value) {
        final Bundle result = new Bundle(1);
        result.putBoolean(KEY_BOOLEAN_RESULT, value);
        return result;
    }

    private Bundle toAuthTokenBundle(final Account account, final String authToken) {
        final Bundle bundle = new Bundle(3);
        bundle.putString(KEY_ACCOUNT_NAME, account.name);
        bundle.putString(KEY_ACCOUNT_TYPE, account.type);
        bundle.putString(KEY_AUTHTOKEN, authToken);
        return bundle;
    }

    /**
     * TODO add all required parameters to perform an online password
     * verification (connection parameters, protocol, username, login, etc.)
     * 
     * @param options
     * 
     * @return
     * @throws AuthenticatorHelperException
     * @throws NetworkErrorException
     */
    private boolean onlinePasswordCheck(final Bundle options) throws AuthenticatorHelperException,
            NetworkErrorException {
        /*
         * TODO use parameters to perform an actual online connection to the
         * mail server in order to verify username/password
         */
        // checkImap();
        // checkPop3();
        // checkWebDav();
        throw new AuthenticatorHelperException(ERROR_CODE_UNSUPPORTED_OPERATION,
                "Online password check not yet supported");
    }

    // private boolean checkWebDav() throws NetworkErrorException {
    // // TODO Auto-generated method stub
    // return false;
    // }
    //
    // private boolean checkPop3() throws NetworkErrorException {
    // // TODO Auto-generated method stub
    // return false;
    // }
    //
    // private boolean checkImap() throws NetworkErrorException {
    // final ImapConnection connection = new ImapConnection(new ImapSettings() {
    //
    // @Override
    // public boolean useCompression(final int type) {
    // // TODO Auto-generated method stub
    // return false;
    // }
    //
    // @Override
    // public void setPathPrefix(final String prefix) {
    // // TODO Auto-generated method stub
    //
    // }
    //
    // @Override
    // public void setPathDelimeter(final String delimeter) {
    // // TODO Auto-generated method stub
    //
    // }
    //
    // @Override
    // public void setCombinedPrefix(final String prefix) {
    // // TODO Auto-generated method stub
    //
    // }
    //
    // @Override
    // public String getUsername() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public int getPort() {
    // // TODO Auto-generated method stub
    // return 0;
    // }
    //
    // @Override
    // public String getPathPrefix() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public String getPathDelimeter() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public String getPassword() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public String getHost() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public int getConnectionSecurity() {
    // // TODO Auto-generated method stub
    // return 0;
    // }
    //
    // @Override
    // public String getCombinedPrefix() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public AuthType getAuthType() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    // });
    // try {
    // connection.open();
    // connection.close();
    // return true;
    // } catch (final AuthenticationFailedException e) {
    // return false;
    // } catch (final Exception e) {
    // throw new NetworkErrorException(e);
    // }
    // }

}
