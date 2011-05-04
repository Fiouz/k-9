package com.fsck.k9.authenticator;

import android.accounts.AccountManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class AuthenticatorService extends Service
{

    private AccountAuthenticator mAccountAuthenticator;

    @Override
    public void onCreate()
    {
        mAccountAuthenticator = new AccountAuthenticator(getApplication());
    }

    @Override
    public IBinder onBind(final Intent intent)
    {
        final String action = intent.getAction();
        if (AccountManager.ACTION_AUTHENTICATOR_INTENT.equals(action))
        {
            return mAccountAuthenticator.getIBinder();
        }
        return null;
    }

    @Override
    public void onDestroy()
    {
        mAccountAuthenticator = null;
        super.onDestroy();
    }

}
