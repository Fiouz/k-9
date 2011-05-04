package com.fsck.k9.authenticator;

import static android.accounts.AccountManager.ERROR_CODE_BAD_ARGUMENTS;
import static android.accounts.AccountManager.ERROR_CODE_BAD_REQUEST;
import static android.accounts.AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION;
import static android.accounts.AccountManager.KEY_ACCOUNT_NAME;
import static android.accounts.AccountManager.KEY_ACCOUNT_TYPE;
import static android.accounts.AccountManager.KEY_AUTHTOKEN;
import static android.accounts.AccountManager.KEY_BOOLEAN_RESULT;
import static android.accounts.AccountManager.KEY_PASSWORD;
import static android.accounts.AccountManager.KEY_USERDATA;
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
 * @author Fiouz
 * @see AbstractAccountAuthenticator
 */
public class AuthenticatorHelper {

    private final AccountManager mAccountManager;

    public AuthenticatorHelper(final Context context) {
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
        final Bundle userdata = options.getBundle(KEY_USERDATA);
        mAccountManager.addAccountExplicitly(account, password, userdata);

        final Bundle result = new Bundle();
        result.putString(KEY_ACCOUNT_NAME, accountName);
        result.putString(KEY_ACCOUNT_TYPE, accountType);

        if (authTokenType != null) {
            final Bundle authTokenBundle = getAuthToken(account, authTokenType, options);
            final String authToken = authTokenBundle.getString(KEY_AUTHTOKEN);
            result.putString(KEY_AUTHTOKEN, authToken);
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
     * TODO add all required parameters to perform an online password
     * verification (connection parameters, protocol, username, login, etc.)
     *
     * @param options
     *
     * @return
     * @throws AuthenticatorHelperException
     */
    private boolean onlinePasswordCheck(final Bundle options) throws AuthenticatorHelperException {
        /*
         * TODO use parameters to perform an actual online connection to the
         * mail server in order to verify username/password
         */
        throw new AuthenticatorHelperException(ERROR_CODE_UNSUPPORTED_OPERATION,
                "Online password check not yet supported");
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
    public Bundle updateCredentials(final Account account, final String authTokenType, final Bundle options)
            throws NetworkErrorException, AuthenticatorHelperException {
        Log.v(K9.LOG_TAG, "Helper.updateCredentials");
        // commented out because there seem to be a bug regarding
        // updateCredentials() throwing an exception when authTokenType is null
        // if (authTokenType != null && !isValidAuthTokenType(authTokenType))
        // {
        // throw new AuthenticatorHelperException(ERROR_CODE_BAD_ARGUMENTS,
        // "Unsupported auth token type: "
        // + authTokenType);
        // }
        if (options == null) {
            throw new AuthenticatorHelperException(ERROR_CODE_BAD_REQUEST, "Missing options");
        }
        final String password = options.getString(KEY_PASSWORD);
        // password may be null here

        Log.v(K9.LOG_TAG, "============== Storing password for account " + account);

        mAccountManager.setPassword(account, password);
        final Bundle result = new Bundle(2);
        result.putString(KEY_ACCOUNT_NAME, account.name);
        result.putString(KEY_ACCOUNT_TYPE, account.type);

        // if (authTokenType != null)
        // {
        // getAuthToken(account, authTokenType, options);
        // }

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
        return toBooleanBundle(false); // TODO
    }

    /**
     * @param authTokenType
     *            Can be {@code null}.
     * @return
     */
    private boolean isValidAuthTokenType(final String authTokenType) {
        // we don't support auth token for now
        return false;
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
        throw new AuthenticatorHelperException(ERROR_CODE_UNSUPPORTED_OPERATION, "No auth token support");
        // final Bundle bundle = new Bundle(3);
        // mAccountManager.setAuthToken(account, authTokenType,
        // "fakeAuthToken");
        // bundle.putString(KEY_ACCOUNT_NAME, account.name);
        // bundle.putString(KEY_ACCOUNT_TYPE, account.type);
        // bundle.putString(KEY_AUTHTOKEN, "fakeAuthToken");
        // return bundle;
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
        // TODO
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
        // TODO for now, allow any account removal
        return toBooleanBundle(true);
    }

    private Bundle toBooleanBundle(final boolean value) {
        final Bundle result = new Bundle(1);
        result.putBoolean(KEY_BOOLEAN_RESULT, value);
        return result;
    }

}
