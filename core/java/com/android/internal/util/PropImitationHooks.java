/*
 * Copyright (C) 2022 Paranoid Android
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.util;

import android.app.Application;
import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import com.android.internal.R;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

public class PropImitationHooks {

    private static final String TAG = "PropImitationHooks";
    private static final boolean DEBUG = true;

    private static final String[] sCertifiedProps =
            Resources.getSystem().getStringArray(R.array.config_certifiedBuildProperties);

    private static final String sStockFp =
            Resources.getSystem().getString(R.string.config_stockFingerprint);

    private static final boolean sSpoofPhotos =
            Resources.getSystem().getBoolean(R.bool.config_spoofGooglePhotos);

    private static final boolean sEnabled =
            SystemProperties.getBoolean("persist.sys.pihooks.enabled", true);

    private static final String PACKAGE_ARCORE = "com.google.ar.core";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PROCESS_GMS_UNSTABLE = PACKAGE_GMS + ".unstable";
    private static final String PACKAGE_GPHOTOS = "com.google.android.apps.photos";
    private static final String PACKAGE_SNAPCHAT = "com.snapchat.android";

    private static final Map<String, Object> sPixelXLProps = Map.of(
        "BRAND", "google",
        "MANUFACTURER", "Google",
        "DEVICE", "marlin",
        "PRODUCT", "marlin",
        "MODEL", "Pixel XL",
        "FINGERPRINT", "google/marlin/marlin:10/QP1A.191005.007.A3/5972272:user/release-keys"
    );

    private static final Set<String> sFeatureBlacklist = Set.of(
        "PIXEL_2017_PRELOAD",
        "PIXEL_2018_PRELOAD",
        "PIXEL_2019_MIDYEAR_PRELOAD",
        "PIXEL_2019_PRELOAD",
        "PIXEL_2020_EXPERIENCE",
        "PIXEL_2020_MIDYEAR_EXPERIENCE",
        "PIXEL_2021_EXPERIENCE",
        "PIXEL_2021_MIDYEAR_EXPERIENCE"
    );

    private static volatile boolean sIsGms = false;
    private static volatile boolean sIsFinsky = false;
    private static volatile boolean sIsPhotos = false;

    private static volatile Handler sHandler;
    private static volatile boolean sIsGmsPatching = false;
    private static final long GMS_PATCH_DURATION = 2000L;

    private static final String[] sOriginalProps = new String[] {
        Build.DEVICE, Build.PRODUCT, Build.MODEL, Build.FINGERPRINT
    };

    public static void setProps(Context context) {
        if (!sEnabled) return;

        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName)) {
            Log.e(TAG, "Null package or process name");
            return;
        }

        sIsGms = packageName.equals(PACKAGE_GMS) && processName.equals(PROCESS_GMS_UNSTABLE);
        sIsFinsky = packageName.equals(PACKAGE_FINSKY);
        sIsPhotos = sSpoofPhotos && packageName.equals(PACKAGE_GPHOTOS);

        /* Set stock fingerprint for ARCore
         * Set Pixel XL for Google Photos and Snapchat
         */
        if (!sStockFp.isEmpty() && packageName.equals(PACKAGE_ARCORE)) {
            dlog("Setting stock fingerprint for: " + packageName);
            setPropValue("FINGERPRINT", sStockFp);
        } else if (sIsPhotos || packageName.equals(PACKAGE_SNAPCHAT)) {
            dlog("Spoofing Pixel XL for: " + packageName);
            sPixelXLProps.forEach((PropImitationHooks::setPropValue));
        }
    }

    private static void setPropValue(String key, Object value){
        try {
            dlog("Setting prop " + key + " to " + value.toString());
            Field field = Build.class.getDeclaredField(key);
            field.setAccessible(true);
            field.set(null, value);
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            Log.e(TAG, "Failed to set prop " + key, e);
        }
    }

    private static boolean isCallerSafetyNet() {
        return sIsGms && Arrays.stream(Thread.currentThread().getStackTrace())
                .anyMatch(elem -> elem.getClassName().contains("DroidGuard"));
    }

    public static void onEngineGetCertificateChain() {
        // Check stack for SafetyNet or Play Integrity
        if (isCallerSafetyNet() || sIsFinsky) {
            dlog("Blocked key attestation sIsGms=" + sIsGms + " sIsFinsky=" + sIsFinsky);
            throw new UnsupportedOperationException();
        }
    }

    private static void setCertifiedProps(String[] props) {
        // sanity check
        if (props.length != 4) {
            Log.e(TAG, "setGmsProps: insufficient array size: " + props.length);
            return;
        }
        setPropValue("DEVICE", props[0]);
        setPropValue("PRODUCT", props[1]);
        setPropValue("MODEL", props[2]);
        setPropValue("FINGERPRINT", props[3]);
    }

    public static void onGetService(String type, String algorithm) {
        // Arrays.stream(Thread.currentThread().getStackTrace()).forEach(elem -> dlog("onGetService stack trace class:" + elem.getClassName()));
        if (isCallerSafetyNet() //&& (algorithm.equals("AndroidCAStore") || algorithm.equals("AndroidKeyStore"))
                /*type.equals("KeyStore")*/) {
            dlog("Begin new GMS patch");
            if (sHandler == null) {
                sHandler = new Handler(Looper.getMainLooper());
            }
            if (sIsGmsPatching) {
                dlog("GMS already patching, restart timer");
                sHandler.removeCallbacksAndMessages(null);
            } else {
                sIsGmsPatching = true;
                setCertifiedProps(sCertifiedProps);
            }
            sHandler.postDelayed(() -> {
                setCertifiedProps(sOriginalProps);
                sIsGmsPatching = false;
                dlog("End new GMS patch");
            }, GMS_PATCH_DURATION);
        }
    }

    public static boolean hasSystemFeature(String name, boolean def) {
        if (sIsPhotos && def && sFeatureBlacklist.stream().anyMatch(name::contains)) {
            dlog("Blocked system feature " + name + " for Google Photos");
            return false;
        }
        return def;
    }

    private static void dlog(String msg) {
      if (DEBUG) Log.d(TAG, msg);
    }
}
