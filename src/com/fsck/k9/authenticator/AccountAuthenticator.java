package com.fsck.k9.authenticator;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import com.fsck.k9.K9;

public class AccountAuthenticator extends AbstractAccountAuthenticator {

    public static final String ACCOUNT_TYPE = "com.fsck.k9.authenticator.AccountType";

    public static final String KEY_UUID = "UUID";

    public static final String PARAM_INTERACTIVE = "interactive";

    private final Context mContext;

    private final AuthenticatorHelper mHelper;

    /**
     * @param context
     * @see AbstractAccountAuthenticator#AbstractAccountAuthenticator(Context)
     */
    public AccountAuthenticator(final Context context) {
        super(context);
        mContext = context;
        mHelper = new AuthenticatorHelper(context);
    }

    @Override
    public Bundle editProperties(final AccountAuthenticatorResponse response, final String accountType) {
        // this method applies to the whole authenticator, not a particular
        // account
        response.onError(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "editProperties not supported");
        return null;
    }

    @Override
    public Bundle addAccount(final AccountAuthenticatorResponse response, final String accountType,
                             final String authTokenType, final String[] requiredFeatures, final Bundle options)
            throws NetworkErrorException {
        // TODO interactive add
        try {
            return mHelper.addAccount(accountType, authTokenType, requiredFeatures, options);
        } catch (final AuthenticatorHelperException e) {
            return e.toBundle();
        }
    }

    @Override
    public Bundle confirmCredentials(final AccountAuthenticatorResponse response, final Account account,
                                     final Bundle options) throws NetworkErrorException {
        // TODO interactive confirmation
        try {
            return mHelper.confirmCredentials(account, options);
        } catch (final AuthenticatorHelperException e) {
            return e.toBundle();
        }
    }

    @Override
    public Bundle updateCredentials(final AccountAuthenticatorResponse response, final Account account,
                                    final String authTokenType, final Bundle options) throws NetworkErrorException {
        Log.v(K9.LOG_TAG, "Authenticator.updateCredentials");
        final Bundle result;
        if (options == null) {
            result = new Bundle(2);
            result.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_BAD_REQUEST);
            result.putString(AccountManager.KEY_ERROR_MESSAGE, "Missing authenticator options");
        } else if (options.getBoolean(PARAM_INTERACTIVE, false)) {
            // TODO Auto-generated method stub
            final Intent intent = new Intent(mContext, AuthenticatorActivity.class);
            intent.putExtra(AuthenticatorActivity.PARAM_USERNAME, account.name);
            intent.putExtra(AuthenticatorActivity.PARAM_AUTHTOKEN_TYPE, authTokenType);
            result = new Bundle(1);
            result.putParcelable(AccountManager.KEY_INTENT, intent);
        } else {
            try {
                result = mHelper.updateCredentials(account, authTokenType, options);
            } catch (final AuthenticatorHelperException e) {
                return e.toBundle();
            }
        }
        return result;
    }

    @Override
    public Bundle hasFeatures(final AccountAuthenticatorResponse response, final Account account,
                              final String[] features) throws NetworkErrorException {
        // TODO asynchronous mode
        try {
            return mHelper.hasFeatures(account, features);
        } catch (final AuthenticatorHelperException e) {
            return e.toBundle();
        }
    }

    @Override
    public Bundle getAuthToken(final AccountAuthenticatorResponse response, final Account account,
                               final String authTokenType, final Bundle options) throws NetworkErrorException {
        // TODO asynchronous mode
        try {
            return mHelper.getAuthToken(account, authTokenType, options);
        } catch (final AuthenticatorHelperException e) {
            return e.toBundle();
        }
    }

    @Override
    public String getAuthTokenLabel(final String authTokenType) {
        return mHelper.getAuthTokenLabel(authTokenType);
    }

    @Override
    public Bundle getAccountRemovalAllowed(final AccountAuthenticatorResponse response, final Account account)
            throws NetworkErrorException {
        // TODO asynchronous mode

        try {
            return mHelper.getAccountRemovalAllowed(account);
        } catch (final AuthenticatorHelperException e) {
            return e.toBundle();
        }
    }

    private Bundle unsupportedOperation(final String message) {
        final Bundle bundle = new Bundle(2);
        bundle.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION);
        bundle.putString(AccountManager.KEY_ERROR_MESSAGE, message);
        return bundle;
    }

}
