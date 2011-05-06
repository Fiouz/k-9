package com.fsck.k9;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import com.fsck.k9.authenticator.AccountAuthenticator;
import com.fsck.k9.authenticator.AuthenticatorConstants;

/**
 *
 * <p>
 * Requires {@link android.Manifest.permission#MANAGE_ACCOUNTS} and
 * {@link android.Manifest.permission#GET_ACCOUNTS} permissions.
 * </p>
 *
 * <p>
 * Not to be invoked from the UI thread.
 * </p>
 *
 * @author Fiouz
 *
 */
public class AccountHelper {

    private static final int TIMEOUT = 10;

    private final String LOG_PREFIX = getClass().getSimpleName() + ": ";

    private AccountManager mAccountManager;

    public AccountHelper(final Context context) {
        mAccountManager = AccountManager.get(context);
    }

    public boolean createAccount(final String uuid, final String displayName, final String password) {
        if (getAccountByName(displayName) != null) {
            // already existing
            return false;
        }
        final AccountManagerFuture<Bundle> accountFuture;
        final Bundle options = new Bundle();
        options.putString(AccountManager.KEY_ACCOUNT_NAME, displayName);
        options.putString(AccountManager.KEY_PASSWORD, password);
        options.putBoolean(AuthenticatorConstants.KEY_ONLINE, false);
        accountFuture = mAccountManager.addAccount(AccountAuthenticator.ACCOUNT_TYPE, null, new String[] {
            "uuid:" + uuid
        }, options, null, null, null);
        try {
            final Bundle result = accountFuture.getResult(TIMEOUT, TimeUnit.SECONDS);
            return result != null && result.containsKey(displayName);
        } catch (final OperationCanceledException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        } catch (final AuthenticatorException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        } catch (final IOException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        }
        return false;
    }

    public boolean removeAccount(final Account account) {
        final AccountManagerFuture<Boolean> bundle = mAccountManager.removeAccount(account, null, null);
        try {
            return bundle.getResult(TIMEOUT, TimeUnit.SECONDS).booleanValue();
        } catch (final OperationCanceledException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        } catch (final AuthenticatorException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        } catch (final IOException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        }
        return false;
    }

    /**
     *
     * <p>
     * Don't invoke this method from the UI thread.
     * </p>
     *
     * @param uuid
     *
     * @return
     */
    public Account findAccountByUuid(final String uuid) {
        final AccountManagerFuture<Account[]> accountsFuture;
        accountsFuture = mAccountManager.getAccountsByTypeAndFeatures(AccountAuthenticator.ACCOUNT_TYPE, new String[] {
            AuthenticatorConstants.FEATURE_UUID_PREFIX + uuid
        }, null, null);
        try {
            final Account[] accounts;
            accounts = accountsFuture.getResult(TIMEOUT, TimeUnit.SECONDS);
            if (accounts.length == 1) {
                return accounts[0];
            } else if (accounts.length > 1) {
                // Error, too many account with that UUID!
                Log.e(K9.LOG_TAG, "More than 1 account with UUID: " + uuid);
            }
        } catch (final OperationCanceledException e) {
            Log.v(K9.LOG_TAG, LOG_PREFIX + "getAccounts operation canceled", e);
        } catch (final AuthenticatorException e) {
            Log.v(K9.LOG_TAG, LOG_PREFIX + "getAccounts AuthenticatorException", e);
        } catch (final IOException e) {
            Log.v(K9.LOG_TAG, LOG_PREFIX + "getAccounts IOException", e);
        }
        return null;
    }

    public Account getAccountByName(final String name) {
        for (final Account account : mAccountManager.getAccountsByType(AccountAuthenticator.ACCOUNT_TYPE)) {
            if (account.name.equals(name)) {
                return account;
            }
        }
        return null;
    }

    /**
     * @param account
     *            Never {@code null}.
     * @param password
     *            Can be {@code null}.
     * @return <code>true</code> if password update went successful,
     *         <code>false</code> otherwise
     */
    public boolean setPassword(final Account account, final String password) {
        final Bundle options = new Bundle();
        options.putString(AccountManager.KEY_PASSWORD, password);
        Log.i(K9.LOG_TAG, "Storing password in AccountManager: " + account);
        final AccountManagerFuture<Bundle> result;
        result = mAccountManager.updateCredentials(account, AuthenticatorConstants.TOKENTYPE_PASSWORD, options, null,
                null, null);
        try {
            result.getResult(TIMEOUT, TimeUnit.SECONDS);
            return true;
        } catch (final OperationCanceledException e) {
            Log.i(K9.LOG_TAG, LOG_PREFIX + "", e);
        } catch (final AuthenticatorException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        } catch (final IOException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        }
        return false;
    }

    public String getPassword(final Account account) {
        final AccountManagerFuture<Bundle> authToken;
        authToken = mAccountManager.getAuthToken(account, AuthenticatorConstants.TOKENTYPE_PASSWORD, false, null, null);
        try {
            final Bundle bundle = authToken.getResult();
            return bundle.getString(AccountManager.KEY_AUTHTOKEN);
        } catch (final OperationCanceledException e) {
            Log.i(K9.LOG_TAG, LOG_PREFIX + "", e);
        } catch (final AuthenticatorException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        } catch (final IOException e) {
            Log.w(K9.LOG_TAG, LOG_PREFIX + "", e);
        }
        return null;
    }

}
