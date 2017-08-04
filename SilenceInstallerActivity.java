package com.android.packageinstaller;

import android.app.Activity;
import android.app.ActivityManagerNative;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.PackageParser;
import android.content.pm.PackageParser.PackageLite;
import android.content.pm.PackageUserState;
import android.content.pm.VerificationParams;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.os.Process;
import android.os.UserManager;
import android.provider.Settings;
import android.util.Log;
import android.widget.Toast;
import android.widget.AppSecurityPermissions;

import com.android.internal.content.PackageHelper;
import com.android.packageinstaller.permission.utils.IoUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * Created by Stary on 2017/8/2.
 * 实现白名单和静默安装
 */

public class SilenceInstallerActivity extends Activity {
    private static final String TAG = "PackageInstaller";
    private static final String BROADCAST_ACTION =
            "com.android.packageinstaller.ACTION_INSTALL_COMMIT";
    private static final String BROADCAST_SENDER_PERMISSION =
            "android.permission.INSTALL_PACKAGES";

    private static final String SCHEME_FILE = "file";
    private static final String SCHEME_CONTENT = "content";
    private static final String SCHEME_PACKAGE = "package";

    private int mSessionId = -1;
    private Uri mPackageURI;
    private Uri mOriginatingURI;
    private Uri mReferrerURI;
    private int mOriginatingUid = VerificationParams.NO_UID;

    private AsyncTask<Uri, Void, File> mStagingAsynTask;

    PackageManager mPm;
    UserManager mUserManager;
    PackageInstaller mInstaller;
    PackageInfo mPkgInfo;
    ApplicationInfo mSourceInfo;

    private DbService dbService;

    // ApplicationInfo object primarily used for already existing applications
    private ApplicationInfo mAppInfo = null;


    private final int INSTALL_COMPLETE = 1;
    private HandlerThread mInstallThread;
    private Handler mInstallHandler;

    /**
     * Get the originating uid if possible, or VerificationParams.NO_UID if not available
     */
    private int getOriginatingUid(Intent intent) {
        // The originating uid from the intent. We only trust/use this if it comes from a
        // system application
        int uidFromIntent = intent.getIntExtra(Intent.EXTRA_ORIGINATING_UID,
                VerificationParams.NO_UID);

        // Get the source info from the calling package, if available. This will be the
        // definitive calling package, but it only works if the intent was started using
        // startActivityForResult,
        ApplicationInfo sourceInfo = getSourceInfo();
        if (sourceInfo != null) {
            if (uidFromIntent != VerificationParams.NO_UID &&
                    (mSourceInfo.privateFlags & ApplicationInfo.PRIVATE_FLAG_PRIVILEGED) != 0) {
                return uidFromIntent;

            }
            // We either didn't get a uid in the intent, or we don't trust it. Use the
            // uid of the calling package instead.
            return sourceInfo.uid;
        }

        // We couldn't get the specific calling package. Let's get the uid instead
        int callingUid;
        try {
            callingUid = ActivityManagerNative.getDefault()
                    .getLaunchedFromUid(getActivityToken());
        } catch (android.os.RemoteException ex) {
            Log.w(TAG, "Could not determine the launching uid.");
            // nothing else we can do
            return VerificationParams.NO_UID;
        }

        // If we got a uid from the intent, we need to verify that the caller is a
        // privileged system package before we use it
        if (uidFromIntent != VerificationParams.NO_UID) {
            String[] callingPackages = mPm.getPackagesForUid(callingUid);
            if (callingPackages != null) {
                for (String packageName : callingPackages) {
                    try {
                        ApplicationInfo applicationInfo =
                                mPm.getApplicationInfo(packageName, 0);

                        if ((applicationInfo.privateFlags & ApplicationInfo.PRIVATE_FLAG_PRIVILEGED)
                                != 0) {
                            return uidFromIntent;
                        }
                    } catch (NameNotFoundException ex) {
                        // ignore it, and try the next package
                    }
                }
            }
        }
        // We either didn't get a uid from the intent, or we don't trust it. Use the
        // calling uid instead.
        return callingUid;
    }

    /**
     * Get the ApplicationInfo for the calling package, if available
     */
    private ApplicationInfo getSourceInfo() {
        String callingPackage = getCallingPackage();
        if (callingPackage != null) {
            try {
                return mPm.getApplicationInfo(callingPackage, 0);
            } catch (NameNotFoundException ex) {
                // ignore
            }
        }
        return null;
    }

    private boolean processPackageUri(final Uri packageUri) {
        mPackageURI = packageUri;

        final String scheme = packageUri.getScheme();

        switch (scheme) {
            case SCHEME_PACKAGE: {
                try {
                    mPkgInfo = mPm.getPackageInfo(packageUri.getSchemeSpecificPart(),
                            PackageManager.GET_PERMISSIONS
                                    | PackageManager.GET_UNINSTALLED_PACKAGES);
                } catch (NameNotFoundException e) {
                }
                if (mPkgInfo == null) {
                    Log.w(TAG, "Requested package " + packageUri.getScheme()
                            + " not available. Discontinuing installation");
                    return false;
                }
            } break;

            case SCHEME_FILE: {
                File sourceFile = new File(packageUri.getPath());
                PackageParser.Package parsed = PackageUtil.getPackageInfo(sourceFile);

                // Check for parse errors
                if (parsed == null) {
                    Log.w(TAG, "Parse error when parsing manifest. Discontinuing installation");
                    return false;
                }
                mPkgInfo = PackageParser.generatePackageInfo(parsed, null,
                        PackageManager.GET_PERMISSIONS, 0, 0, null,
                        new PackageUserState());
            } break;

            case SCHEME_CONTENT: {
                mStagingAsynTask = new StagingAsyncTask();
                mStagingAsynTask.execute(packageUri);
                return false;
            }

            default: {
                Log.w(TAG, "Unsupported scheme " + scheme);
                return false;
            }
        }
        return true;
    }

    private final class StagingAsyncTask extends AsyncTask<Uri, Void, File> {
        private static final long SHOW_EMPTY_STATE_DELAY_MILLIS = 300;

        private final Runnable mEmptyStateRunnable = new Runnable() {
            @Override
            public void run() {
            }
        };

        @Override
        protected void onPreExecute() {
            getWindow().getDecorView().postDelayed(mEmptyStateRunnable,
                    SHOW_EMPTY_STATE_DELAY_MILLIS);
        }

        @Override
        protected File doInBackground(Uri... params) {
            if (params == null || params.length <= 0) {
                return null;
            }
            Uri packageUri = params[0];
            File sourceFile = null;
            try {
                sourceFile = File.createTempFile("package", ".apk", getCacheDir());
                try (
                        InputStream in = getContentResolver().openInputStream(packageUri);
                        OutputStream out = (in != null) ? new FileOutputStream(
                                sourceFile) : null;
                ) {
                    // Despite the comments in ContentResolver#openInputStream
                    // the returned stream can be null.
                    if (in == null) {
                        return null;
                    }
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) >= 0) {
                        // Be nice and respond to a cancellation
                        if (isCancelled()) {
                            return null;
                        }
                        out.write(buffer, 0, bytesRead);
                    }
                }
            } catch (IOException ioe) {
                Log.w(TAG, "Error staging apk from content URI", ioe);
                if (sourceFile != null) {
                    sourceFile.delete();
                }
            }
            return sourceFile;
        }

        @Override
        protected void onPostExecute(File file) {
            getWindow().getDecorView().removeCallbacks(mEmptyStateRunnable);
            if (isFinishing() || isDestroyed()) {
                return;
            }
            if (file == null) {
                return;
            }

            Uri fileUri = Uri.fromFile(file);

            boolean wasSetUp = processPackageUri(fileUri);
            if (wasSetUp) {
                checkIfAllowedAndInitiateInstall(false);
            }
        }

        @Override
        protected void onCancelled(File file) {
            getWindow().getDecorView().removeCallbacks(mEmptyStateRunnable);
        }
    }

    /**
     * 是否来自未知源的请求安装
     */
    private boolean isInstallRequestFromUnknownSource(Intent intent) {
        String callerPackage = getCallingPackage();
        if (callerPackage != null && intent.getBooleanExtra(
                Intent.EXTRA_NOT_UNKNOWN_SOURCE, false)) {
            try {
                mSourceInfo = mPm.getApplicationInfo(callerPackage, 0);
                if (mSourceInfo != null) {
                    if ((mSourceInfo.privateFlags & ApplicationInfo.PRIVATE_FLAG_PRIVILEGED)
                            != 0) {
                        // Privileged apps are not considered an unknown source.
                        return false;
                    }
                }
            } catch (NameNotFoundException e) {
            }
        }
        return true;
    }

    /**
     * 用户在设置中是否启用了未知源
     */
    private boolean isUnknownSourcesEnabled() {
        return Settings.Secure.getInt(getContentResolver(),
                Settings.Secure.INSTALL_NON_MARKET_APPS, 0) > 0;
    }

    /**
     * 设备管理员是否限制安装从未知来源
     */
    private boolean isUnknownSourcesDisallowed() {
        return mUserManager.hasUserRestriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES);
    }

    /**
     * 检查是否允许安装包并在允许的情况下启动安装
     *
     * @param ignoreUnknownSourcesSettings 是否忽略
     */
    private void checkIfAllowedAndInitiateInstall(boolean ignoreUnknownSourcesSettings) {
        // Block the install attempt on the Unknown Sources setting if necessary.
        final boolean requestFromUnknownSource = isInstallRequestFromUnknownSource(getIntent());
        if (!requestFromUnknownSource) {
            initiateInstall();
            return;
        }

        // If the admin prohibits it, or we're running in a managed profile, just show error
        // and exit. Otherwise show an option to take the user to Settings to change the setting.
        final boolean isManagedProfile = mUserManager.isManagedProfile();
        if (isUnknownSourcesDisallowed()) {
            if ((mUserManager.getUserRestrictionSource(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES,
                    Process.myUserHandle()) & UserManager.RESTRICTION_SOURCE_SYSTEM) != 0) {
                if (ignoreUnknownSourcesSettings) {
                    initiateInstall();
                } else {
                    Toast.makeText(getApplicationContext(), "please open the unknown source", Toast.LENGTH_SHORT).show();
                    clearCachedApkIfNeededAndFinish();
                }
            } else {
                Toast.makeText(getApplicationContext(), "installation failed", Toast.LENGTH_SHORT).show();
                clearCachedApkIfNeededAndFinish();
            }
        } else if (!isUnknownSourcesEnabled() && isManagedProfile) {
            Toast.makeText(getApplicationContext(), "please open the unknown source", Toast.LENGTH_SHORT).show();
            clearCachedApkIfNeededAndFinish();
        } else if (!isUnknownSourcesEnabled()) {
            if (ignoreUnknownSourcesSettings) {
                initiateInstall();
            } else {
                Toast.makeText(getApplicationContext(), "please open the unknown source", Toast.LENGTH_SHORT).show();
                clearCachedApkIfNeededAndFinish();
            }
        } else {
            initiateInstall();
        }
    }

    /**
     * 检查白名单
     */
    private void checkWhiteList() {
        List<String> mList = dbService.getPackages();
        if (mList != null && mList.size() > 0) {
            if (!isHave(mList)) {
                Toast.makeText(getApplicationContext(), "This APK not in white list!", Toast.LENGTH_SHORT).show();
                clearCachedApkIfNeededAndFinish();
            }
        } else {
            Toast.makeText(getApplicationContext(), "This APK not in white list!", Toast.LENGTH_SHORT).show();
            clearCachedApkIfNeededAndFinish();
        }
    }

    private boolean isHave(List<String> mList) {
        for (String string : mList) {
            if (string.equals(mPkgInfo.packageName)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void onCreate(Bundle icicle) {
        super.onCreate(icicle);
        mPm = getPackageManager();
        mInstaller = mPm.getPackageInstaller();
        mUserManager = (UserManager) getSystemService(Context.USER_SERVICE);
        //初始化数据库
        dbService = DbService.getInstance(this);

        final Intent intent = getIntent();
        mOriginatingUid = getOriginatingUid(intent);

        final Uri packageUri;

        if (PackageInstaller.ACTION_CONFIRM_PERMISSIONS.equals(intent.getAction())) {
            final int sessionId = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1);
            final PackageInstaller.SessionInfo info = mInstaller.getSessionInfo(sessionId);
            if (info == null || !info.sealed || info.resolvedBaseCodePath == null) {
                Log.w(TAG, "Session " + mSessionId + " in funky state; ignoring");
                Toast.makeText(getApplicationContext(), "Installation failed", Toast.LENGTH_SHORT).show();
                finish();
                return;
            }

            mSessionId = sessionId;
            packageUri = Uri.fromFile(new File(info.resolvedBaseCodePath));
            mOriginatingURI = null;
            mReferrerURI = null;
        } else {
            mSessionId = -1;
            packageUri = intent.getData();
            mOriginatingURI = intent.getParcelableExtra(Intent.EXTRA_ORIGINATING_URI);
            mReferrerURI = intent.getParcelableExtra(Intent.EXTRA_REFERRER);
        }

        // if there's nothing to do, quietly slip into the ether
        if (packageUri == null) {
            Log.w(TAG, "Unspecified source");
            Toast.makeText(getApplicationContext(), "Unspecified source", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        if (DeviceUtils.isWear(this)) {
            Toast.makeText(getApplicationContext(), "Installation failed", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        if (!processPackageUri(packageUri)) {
            Toast.makeText(getApplicationContext(), "Installation failed", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        final String scheme = mPackageURI.getScheme();
        if (scheme != null && !"file".equals(scheme) && !"package".equals(scheme)) {
            throw new IllegalArgumentException("unexpected scheme " + scheme);
        }

        mInstallThread = new HandlerThread("InstallThread");
        mInstallThread.start();
        mInstallHandler = new Handler(mInstallThread.getLooper());

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(BROADCAST_ACTION);
        registerReceiver(mBroadcastReceiver, intentFilter, BROADCAST_SENDER_PERMISSION, null /*scheduler*/);

        checkIfAllowedAndInitiateInstall(false);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(mBroadcastReceiver);
        mInstallThread.getLooper().quitSafely();
    }

    @Override
    public void onBackPressed() {
        if (mSessionId != -1) {
            mInstaller.setPermissionsResult(mSessionId, false);
        }
        clearCachedApkIfNeededAndFinish();
    }

    /**
     * 启动安装
     */
    private void initiateInstall() {
        String pkgName = mPkgInfo.packageName;
        // Check if there is already a package on the device with this name
        // but it has been renamed to something else.
        String[] oldName = mPm.canonicalToCurrentPackageNames(new String[]{pkgName});
        if (oldName != null && oldName.length > 0 && oldName[0] != null) {
            pkgName = oldName[0];
            mPkgInfo.packageName = pkgName;
            mPkgInfo.applicationInfo.packageName = pkgName;
        }
        // Check if package is already installed. display confirmation dialog if replacing pkg
        try {
            // This is a little convoluted because we want to get all uninstalled
            // apps, but this may include apps with just data, and if it is just
            // data we still want to count it as "installed".
            mAppInfo = mPm.getApplicationInfo(pkgName,
                    PackageManager.GET_UNINSTALLED_PACKAGES);
            if ((mAppInfo.flags & ApplicationInfo.FLAG_INSTALLED) == 0) {
                mAppInfo = null;
            }
        } catch (NameNotFoundException e) {
            mAppInfo = null;
        }

        checkWhiteList();
        startInstall();
    }

    /**
     * 开始安装
     */
    private void startInstall() {
        ApplicationInfo appInfo = mPkgInfo.applicationInfo;
        final PackageManager pm = getPackageManager();
        final int installFlags = getInstallFlags(appInfo.packageName);

        if ((installFlags & PackageManager.INSTALL_REPLACE_EXISTING) != 0) {
            Log.w(TAG, "Replacing package:" + appInfo.packageName);
        }

        if ("package".equals(mPackageURI.getScheme())) {
            try {
                pm.installExistingPackage(appInfo.packageName);
                onPackageInstalled(PackageInstaller.STATUS_SUCCESS);
            } catch (PackageManager.NameNotFoundException e) {
                onPackageInstalled(PackageInstaller.STATUS_FAILURE_INVALID);
            }
        } else {
            final PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                    PackageInstaller.SessionParams.MODE_FULL_INSTALL);
            params.referrerUri = mReferrerURI;
            params.originatingUri = mOriginatingURI;
            params.originatingUid = mOriginatingUid;

            File file = new File(mPackageURI.getPath());
            try {
                PackageLite pkg = ƒ.parsePackageLite(file, 0);
                params.setAppPackageName(pkg.packageName);
                params.setInstallLocation(pkg.installLocation);
                params.setSize(
                        PackageHelper.calculateInstalledSize(pkg, false, params.abiOverride));
            } catch (PackageParser.PackageParserException e) {
                Log.e(TAG, "Cannot parse package " + file + ". Assuming defaults.");
                Log.e(TAG, "Cannot calculate installed size " + file + ". Try only apk size.");
                params.setSize(file.length());
            } catch (IOException e) {
                Log.e(TAG, "Cannot calculate installed size " + file + ". Try only apk size.");
                params.setSize(file.length());
            }

            mInstallHandler.post(new Runnable() {
                @Override
                public void run() {
                    doPackageStage(pm, params);
                }
            });
        }
    }

    int getInstallFlags(String packageName) {
        PackageManager pm = getPackageManager();
        try {
            PackageInfo pi =
                    pm.getPackageInfo(packageName, PackageManager.GET_UNINSTALLED_PACKAGES);
            if (pi != null) {
                return PackageManager.INSTALL_REPLACE_EXISTING;
            }
        } catch (NameNotFoundException e) {
        }
        return 0;
    }

    void onPackageInstalled(int statusCode) {
        Message msg = mHandler.obtainMessage(INSTALL_COMPLETE);
        msg.arg1 = statusCode;
        mHandler.sendMessage(msg);
    }

    private void doPackageStage(PackageManager pm, PackageInstaller.SessionParams params) {
        final PackageInstaller packageInstaller = pm.getPackageInstaller();
        PackageInstaller.Session session = null;
        try {
            final String packageLocation = mPackageURI.getPath();
            final File file = new File(packageLocation);
            final int sessionId = packageInstaller.createSession(params);
            final byte[] buffer = new byte[65536];

            session = packageInstaller.openSession(sessionId);

            final InputStream in = new FileInputStream(file);
            final long sizeBytes = file.length();
            final OutputStream out = session.openWrite("PackageInstaller", 0, sizeBytes);
            try {
                int c;
                while ((c = in.read(buffer)) != -1) {
                    out.write(buffer, 0, c);
                    if (sizeBytes > 0) {
                        final float fraction = ((float) c / (float) sizeBytes);
                        session.addProgress(fraction);
                    }
                }
                session.fsync(out);
            } finally {
                IoUtils.closeQuietly(in);
                IoUtils.closeQuietly(out);
            }

            // Create a PendingIntent and use it to generate the IntentSender
            Intent broadcastIntent = new Intent(BROADCAST_ACTION);
            PendingIntent pendingIntent = PendingIntent.getBroadcast(
                    SilenceInstallerActivity.this /*context*/,
                    sessionId,
                    broadcastIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT);
            session.commit(pendingIntent.getIntentSender());
        } catch (IOException e) {
            onPackageInstalled(PackageInstaller.STATUS_FAILURE);
        } finally {
            IoUtils.closeQuietly(session);
        }
    }

    private Handler mHandler = new Handler() {
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case INSTALL_COMPLETE:
                    if (msg.arg1 == PackageInstaller.STATUS_SUCCESS) {
                        // 成功安装应用程序
                        Toast.makeText(getApplicationContext(), getString(R.string.install_done), Toast.LENGTH_SHORT).show();
                    } else if (msg.arg1 == PackageInstaller.STATUS_FAILURE_STORAGE) {
                        // 由于空间不足而导致安装失败
                        Toast.makeText(getApplicationContext(), getString(R.string.out_of_space_dlg_text), Toast.LENGTH_SHORT).show();
                    } else {
                        // Generic error handling for all other error codes.
                        int centerExplanationLabel = getExplanationFromErrorCode(msg.arg1);
                        if (centerExplanationLabel != -1) {
                            // 由于其他原因导致安装失败
                            Toast.makeText(getApplicationContext(), getString(centerExplanationLabel), Toast.LENGTH_SHORT).show();
                        }
                    }
                    clearCachedApkIfNeededAndFinish();
                    break;
                default:
                    break;
            }
        }
    };

    private int getExplanationFromErrorCode(int errCode) {
        Log.d(TAG, "Installation error code: " + errCode);
        switch (errCode) {
            case PackageInstaller.STATUS_FAILURE_BLOCKED:
                return R.string.install_failed_blocked;
            case PackageInstaller.STATUS_FAILURE_CONFLICT:
                return R.string.install_failed_conflict;
            case PackageInstaller.STATUS_FAILURE_INCOMPATIBLE:
                return R.string.install_failed_incompatible;
            case PackageInstaller.STATUS_FAILURE_INVALID:
                return R.string.install_failed_invalid_apk;
            default:
                return -1;
        }
    }

    private final BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            final int statusCode = intent.getIntExtra(
                    PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
            onPackageInstalled(statusCode);
        }
    };

    private void clearCachedApkIfNeededAndFinish() {
        // If we are installing from a content:// the apk is copied in the cache
        // dir and passed in here. As we aren't started for a result because our
        // caller needs to be able to forward the result, here we make sure the
        // staging file in the cache dir is removed.
        if ("file".equals(mPackageURI.getScheme()) && mPackageURI.getPath() != null
                && mPackageURI.getPath().startsWith(getCacheDir().toString())) {
            File file = new File(mPackageURI.getPath());
            file.delete();
        }
        finish();
    }
}
