import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* 
 * AES (Advanced Encryption Standard)
 * 유형: 대칭 암호화
 * 핵심 개념: AES는 128비트 블록에 128, 192, 256비트 키를 사용하는 매우 안전하고 효율적인 블록 암호화 알고리즘입니다. 
 * AES는 현재 가장 널리 사용되는 암호화 표준입니다.
 * 
 * 강점: AES는 256비트 키를 사용할 경우 매우 강력한 보안을 제공하며, 현재까지 실질적인 취약점이 발견되지 않았습니다.
 * 
 * 사용 사례:
 * 데이터 암호화(디스크 암호화, 파일 암호화 등)
 * 보안 통신(VPN, SSL/TLS)
 * 무선 네트워크 보안(WPA2 암호화)
 * 
 * 장점:
 * 매우 강력하고 효율적인 암호화
 * 광범위하게 사용되고 신뢰할 수 있음
 * 대용량 데이터 암호화에 적합
 * 
 * 단점:
 * 경량 암호화에 비해 계산 복잡도가 높음(그러나 여전히 매우 효율적임)
 * 
 * 차이점 요약:
 * RSA는 키 교환과 디지털 서명에 사용되는 비대칭 암호화입니다.
 * TEA는 경량 암호화로, 빠르고 간단하지만 현대적인 알고리즘보다 보안성이 낮습니다.
 * AES는 대용량 데이터 암호화에 적합한 대칭 암호화 알고리즘으로, 매우 안전하고 효율적입니다.
 * 
 */
public class AES {
	public static byte[] ivBytes = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	private String DEAFULT_KEY = "test";  
	
	
	public AES() throws UnsupportedEncodingException {
		String defaultKey = DEAFULT_KEY;
        defaultKey = keyMake(defaultKey);
		defaultKey = defaultKey.substring( 0, 16 );
		DEAFULT_KEY = defaultKey;
	}

	private String keyMake( String key ) throws UnsupportedEncodingException {
		String defaultKey = key;
		if(key.length() < 16) {
			while(defaultKey.length() < 16) {
				defaultKey += "N";
			}
		} else if(key.length() > 16) {
			defaultKey = key.substring( 0, 16 );
		}
		return defaultKey;
	}

	public String AES_Encode(String str)	throws java.io.UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,	IllegalBlockSizeException, BadPaddingException {
		return AES_Encode(str, DEAFULT_KEY);
	}

	public String AES_Decode(String str)	throws java.io.UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return AES_Decode(str, DEAFULT_KEY);
	}
	
	public String AES_Encode(String str, String key)	throws java.io.UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,	IllegalBlockSizeException, BadPaddingException {
		String enkey = keyMake(key);
		byte[] textBytes = str.getBytes("UTF-8");
		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		     SecretKeySpec newKey = new SecretKeySpec(enkey.getBytes("UTF-8"), "AES");
		     Cipher cipher = null;
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);
		// return Base64.encodeBase64String(cipher.doFinal(textBytes));
        return Base64.getEncoder().encodeToString(cipher.doFinal(textBytes));
	}

	public String AES_Decode(String str, String key) throws java.io.UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		String enkey = keyMake(key);
		byte[] textBytes = Base64.getDecoder().decode(str);
		//byte[] textBytes = str.getBytes("UTF-8");
		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec newKey = new SecretKeySpec(enkey.getBytes("UTF-8"), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		cipher.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
		return new String(cipher.doFinal(textBytes), "UTF-8");
	}
}
