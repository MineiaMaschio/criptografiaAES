package br.com.criptografiaAES.criptografia;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

@Service
public class CriptografiaAESService {

	private static byte[] converterChave(String chave) {
		byte[] key = null;
		try {
			key = chave.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
		} catch (Exception e) {
			// TODO: handle exception
		}
		return key;
	}

	public byte[] criptografar(byte[] textoCriptografar, String chave, String nomeArquivoDestino) {
		try {
			SecretKeySpec key1 = new SecretKeySpec(converterChave(chave), "AES");

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

			cipher.init(Cipher.ENCRYPT_MODE, key1);

			byte[] encrypted = cipher.doFinal(textoCriptografar);

			// C:\Temp

			FileWriter arq = new FileWriter("C:\\Temp\\" + nomeArquivoDestino + ".txt");
			PrintWriter gravarArq = new PrintWriter(arq);

			String hex = new BigInteger(1, encrypted).toString(16);
			gravarArq.printf(hex);
			arq.close();

			return encrypted;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String decrypt(byte[] byteText, String chave) {
		try {
			SecretKeySpec key1 = new SecretKeySpec(converterChave(chave), "AES");

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

			cipher.init(Cipher.DECRYPT_MODE, key1);

			byte[] decrypted = cipher.doFinal(byteText);
			return new String(decrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}

	}
}
