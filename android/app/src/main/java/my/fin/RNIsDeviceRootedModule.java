
package my.fin;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;
import com.facebook.soloader.SoLoader;

import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.app.KeyguardManager;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.util.Base64;
import android.widget.Toast;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RNIsDeviceRootedModule extends ReactContextBaseJavaModule {

	private final ReactApplicationContext reactContext;

	public RNIsDeviceRootedModule(ReactApplicationContext reactContext) {
		super(reactContext);
		this.reactContext = reactContext;
	}

	@Override
	public String getName() {
		return "RNIsDeviceRooted";
	}

	@ReactMethod
	public void isDeviceRooted(Promise promise) {
		try {
			boolean isRooted = checkRootMethod1() || checkRootMethod2() || checkRootMethod3();
			promise.resolve(isRooted);
		} catch (Exception e) {
			promise.reject(e);
		}
	}

	@ReactMethod
	public void isDeviceLocked(Promise promise) {
		try {
			boolean isLocked = isLockScreenDisabled();
			promise.resolve(isLocked);
		} catch (Exception e) {
			promise.reject(e);
		}
	}

	// saeed yousefi start
	// &*************************************************************

	@ReactMethod
	public  void encryptByPublicKey(String plain, String publicKey,Promise promise) {

		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		} catch (NoSuchAlgorithmException e) {
			promise.resolve(e);
		} catch (NoSuchProviderException e) {
			promise.resolve(e);
		} catch (NoSuchPaddingException e) {
			promise.resolve(e);
		}
		try {
			cipher.init(Cipher.ENCRYPT_MODE, stringToPublicKey(publicKey,promise));
		} catch (InvalidKeyException e) {
			promise.resolve(e);
		} catch (InvalidKeySpecException e) {
			promise.resolve(e);
		}
		byte[] encryptedBytes = new byte[0];
		try {
			encryptedBytes = cipher.doFinal(plain.getBytes(Charset.forName("UTF-8")));
		} catch (IllegalBlockSizeException e) {
			promise.resolve(e);
		} catch (BadPaddingException e) {
			promise.resolve(e);
		}
		String b64= Base64.encodeToString(encryptedBytes, Base64.DEFAULT).replace("\n", "");
		promise.resolve(b64);
	}

	private PublicKey stringToPublicKey(String publicKeyString,Promise promise) throws InvalidKeySpecException {
		byte[] keyBytes = Base64.decode(publicKeyString, Base64.DEFAULT);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			promise.reject(e);
		}
		return keyFactory.generatePublic(spec);
	}

	@ReactMethod
	public void isUnSafe(Promise promise) {
		try {
			String msg = "";
			boolean isUnSafe = false;
			if (isInstallHackApplication(this.reactContext)) {
				promise.resolve(
						"به دلیل نصب نرم افزارهای مشکوک روی گوشی شما برنامه قابل اجرا نیست، برای اجرا این اپلیکیشن ها مشکوک را از گوشی خود پاک کنید");
			} else if (isReSignApplication(this.reactContext)) {
				promise.resolve(
						"اپلیکیشن دارای امضای نا معتبر بوده و قابل اجرا نیست، برنامه اصلی را از mcs.mci.ir نصب کنید.");
			} else if (isDebugMode(this.reactContext)) {
				promise.resolve("اپلیکیشن در حالت دیباگ بوده و قابل اجرا نیست.");
			} else if (isEmulator(this.reactContext)) {
				promise.resolve("اپلیکیشن روی شبیه ساز قابل اجرا نیست.");
			} else
				promise.resolve("");

		} catch (Exception e) {
			promise.reject(e);
		}

	}

	// written by saeed yousefi for prevent resignature and release by hackers
	private static boolean isReSignApplication(Context con) {
		PackageManager pm = con.getPackageManager();
		try {
			PackageInfo myPackageInfo = pm.getPackageInfo(con.getPackageName(), PackageManager.GET_SIGNATURES);
			String mySig = myPackageInfo.signatures[0].toCharsString();
			boolean isResign = !mySig.equals(
					// "308201dd30820146020101300d06092a864886f70d010105050030373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b3009060355040613025553301e170d3139303232333037333033345a170d3439303231353037333033345a30373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b300906035504061302555330819f300d06092a864886f70d010101050003818d0030818902818100a872a967979c5421024171cc926ec96a14ff31a28b720dbfabd10184e938149404e3851726581cb537781b2013e8262e370d9321c04fcdebc8a69d2c061923e523529c948739216496e7530cab8f47d67f423cf3b168bc3ac2b3181111f960df93ff9aa376acb79f83a68baf6bfdd31437151213fddd059fee7bffcfc77745cd0203010001300d06092a864886f70d010105050003818100158e86619f6ad44e5d85438e21784931bf98d600eeea87849693a09de864681cdc87dfa8a1becb3f17b51f8f0651b5684e718333aea1ae2e5f5c0c73112b43ef961ee76229fdc7f8d95120ebbbf9eda8460b36e975732e8310fd3dfe5b3e7b34abca766aaa9c5bb0e26137b72eef4259d72dbfa4c1a5732fefd8b81146415424"
					"3082037b30820263a00302010202044566573e300d06092a864886f70d01010b0500306d310b3009060355040613024952310f300d0603550408130654656872616e310f300d0603550407130654656872616e310d300b060355040a13045465636831133011060355040b130a546563686e6f6c6f6779311830160603550403130f5061727469616e20436f6d70616e793020170d3139303630333130333634355a180f32313139303531303130333634355a306d310b3009060355040613024952310f300d0603550408130654656872616e310f300d0603550407130654656872616e310d300b060355040a13045465636831133011060355040b130a546563686e6f6c6f6779311830160603550403130f5061727469616e20436f6d70616e7930820122300d06092a864886f70d01010105000382010f003082010a0282010100c3f7578bebc2ae2efc21b71a3f9eb93c0546c72b7f8ec53d5c61c2ff26cca2b35366b3640436f3848d229e37b50dbcb9cfdd570dff751b43b855c218131b2fe47b077bb55733a659126cc88f44a48b67a9e9b0444408e370182d0814bb7ecc8cc7ccfaedd8dd722c53d69e3a2c09fa4d9dd5730b716d95e84d4028d108ce3c68d77f16784f5a70acfd08ce377bdfe62e6e666edd99840dfa643d5f0d24eb1943beca6f403fe90a97357e0b2a54a044efbec3bb596c22638c8b2824c8d237deda3964e754a0fae259e25e704d5d69be73165747733d7912b2b847ee70d904750a40e5ce7b8adc7be2847dde33b0662b59753e80c5843fb1738b47903478fc97830203010001a321301f301d0603551d0e0416041454f90d1733ad971e2aac898c98b7d89e3c733259300d06092a864886f70d01010b050003820101009c83b988a221f6efab899cc4b8c287834bf5e0d4cc4c71683dba63940278e6ac3f4d97b00a617e7416afc19fc665cf8582cf7cad97d801113b10060551c8bd64cd7a351c3cc83da7652e2469a2f3e284f3edd58866d32459ba89f9f9549352cf32a4c2330dcf1b02dc919b29b90b1dafae2c062f71ccaf98882f0cd60cd2e0cdc14c0a56eece9b7901d4fceeb0d117e89710fb2c22bed66615b9402dbf9143bf75b8f85a4165b7f17328eec16533e705328bdd83fed8af8a725f83016acbd5cbfdcc26f115816b49606b8bd5cfff5743be39d282aed3aea5c5650a2681574535500a170e85d51ecf71dc5f0233b751f725c6edd3161898518e9217b9d2961c83");
			// if (isResign) {
			// WebView theWebPage = new WebView(this);
			// theWebPage.loadUrl("http://www.google.com/search?q=" + mySig);
			// }
			return isResign;
		} catch (PackageManager.NameNotFoundException e) {
			e.printStackTrace();

		}
		return false;
	}

	private static boolean isEmulator(Context context) {

		String buildDetails = (Build.FINGERPRINT + Build.DEVICE + Build.MODEL + Build.BRAND + Build.PRODUCT
				+ Build.MANUFACTURER + Build.HARDWARE);

		if (buildDetails.contains("generic") || buildDetails.contains("unknown") || buildDetails.contains("emulator")
				|| buildDetails.contains("sdk") || buildDetails.contains("genymotion") || buildDetails.contains("x86") // this
				// includes
				// vbox86
				|| buildDetails.contains("goldfish") || buildDetails.contains("test-keys"))
			return true;

		TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
		String non = tm.getNetworkOperatorName();
		if (non.equals("android"))
			return true;
//commented for samsung device
		// if (new File("/init.goldfish.rc").exists())
		// 	return true;

		return false;
	}

	private static boolean isDebugMode(Context con) {
		// موقع بیلد از کامنت خارج شد

		if (0 != (con.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE))
			return true;

		if (android.os.Debug.isDebuggerConnected())
			return true;

		if (com.facebook.react.BuildConfig.DEBUG)
			return true;

		return false;
	}

	private static boolean isInstallHackApplication(Context con) {

		PackageManager pm = con.getPackageManager();
		List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
		String installedApp = "";
		for (int i = 0; i < packages.size(); i++) {
			installedApp = installedApp + packages.get(i).packageName + ",";

		}
		return installedApp.indexOf("supersu") > -1 || installedApp.indexOf("magisk") > -1
				|| installedApp.indexOf("superuser") > -1 || installedApp.indexOf("kingRoot") > -1
				|| installedApp.indexOf("iroot") > -1 || installedApp.indexOf("towelroot") > -1
				|| installedApp.indexOf("one click root") > -1 || installedApp.indexOf("vroot") > -1
				|| installedApp.indexOf("supersu") > -1 || installedApp.indexOf("root") > -1
				|| installedApp.indexOf("cyanogenmod") > -1 || installedApp.indexOf("lineageos") > -1
				|| installedApp.indexOf("omnirom") > -1 || installedApp.indexOf("magiskhide") > -1
				|| installedApp.indexOf("suhide") > -1 || installedApp.indexOf("xposed") > -1
				|| installedApp.indexOf("cydia ") > -1 || installedApp.indexOf("substrate") > -1
				|| installedApp.indexOf("ddi") > -1 || installedApp.indexOf("frida") > -1;
	}

	// saeed ends ***************

	private boolean isLockScreenDisabled() {
		KeyguardManager km = (KeyguardManager) this.reactContext.getSystemService(Context.KEYGUARD_SERVICE);
		if (km.isKeyguardSecure())
			return true;
		else
			return false;
	}

	private static boolean checkRootMethod1() {
		String buildTags = android.os.Build.TAGS;
		return buildTags != null && buildTags.contains("test-keys");
	}

	private static boolean checkRootMethod2() {
		String[] paths = { "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
				"/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
				"/data/local/su" };
		for (String path : paths) {
			if (new File(path).exists())
				return true;
		}
		return false;
	}

	private static boolean checkRootMethod3() {
		Process process = null;
		try {
			process = Runtime.getRuntime().exec(new String[] { "/system/xbin/which", "su" });
			BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
			if (in.readLine() != null)
				return true;
			return false;
		} catch (Throwable t) {
			return false;
		} finally {
			if (process != null)
				process.destroy();
		}
	}
}
