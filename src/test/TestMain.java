package test;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;


public class TestMain {
	public static void main(String[] args){
		try {
			String text = "test String";
			KeyPairGenerator kpg =  KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1028);
			KeyPair keyPair = kpg.generateKeyPair();
			
			PrivateKey privatekey = keyPair.getPrivate();
			System.out.println("java私钥格式："+privatekey.getFormat());
			PublicKey publickey = keyPair.getPublic();
			System.out.println("privatekey"+privatekey.toString());
			System.out.println("privatekeyPrivateExponent"+((RSAPrivateKey)privatekey).getPrivateExponent().toString());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
			//从字符串转为密钥对象中转对象
			X509EncodedKeySpec keySpecStr2Obj = new X509EncodedKeySpec(publickey.toString().getBytes()); 
            //
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(((RSAPrivateKey)privatekey).getModulus(), ((RSAPrivateKey)privatekey).getPrivateExponent());
			PrivateKey ppk = keyFactory.generatePrivate(keySpec);
			System.out.println("=========ppk:"+ppk.toString());
            System.out.println("publickey"+publickey.toString());
			System.out.println("publickeyPrivateExponent"+((RSAPublicKey)publickey).getPublicExponent().toString());
			try {
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, publickey);
				byte[] encryptb = cipher.doFinal(text.getBytes());
				Base64 base64 = new Base64();  
				
				System.out.println("------------publickey:"+base64.encode(publickey.getEncoded()));
				System.out.println("------------privatekey:"+base64.encode(privatekey.getEncoded()));
				System.out.println("---------------------------------");
		        System.out.println("明文报文："+text);
	            String cipherTextBase64 = base64.encode(encryptb);  
	            System.out.println("---------------------------------");
	            System.out.println("base64 转码未加密报文："+base64.encode(text.getBytes()));
	            System.out.println("---------------------------------");
	            System.out.println("base64 转码加密报文："+cipherTextBase64);
	            cipher.init(Cipher.DECRYPT_MODE, privatekey);
	            
	            byte[] deencryptb = cipher.doFinal(base64.decode(cipherTextBase64));
	            System.out.println("---------------------------------");
	            System.out.println("解密后报文："+new String(deencryptb));
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	
}
