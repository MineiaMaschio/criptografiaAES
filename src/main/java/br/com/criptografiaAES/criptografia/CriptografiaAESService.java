package br.com.criptografiaAES.criptografia;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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

	// Retorna index para a lista RoundConstant
	public static int retornaposicaoRoundConstant(int i) {
		if (i <= 6) {
			return 0;
		}
		if (i <= 10) {
			return 1;
		}
		if (i <= 14) {
			return 2;
		}
		if (i <= 18) {
			return 3;
		}
		if (i <= 22) {
			return 4;
		}
		if (i <= 26) {
			return 5;
		}
		if (i <= 30) {
			return 6;
		}
		if (i <= 34) {
			return 7;
		}
		if (i <= 38) {
			return 8;
		}
		if (i <= 42) {
			return 9;
		}
		return i;
	}

	public static List<List<Integer>> expansaoChave(String chave) {
		// Seperar a chave por virgula
		String[] separadoVirgula = chave.split(",");

		// Lista de inteiros
		List<Integer> inteiros = new ArrayList<>();

		// Transformar a lista de string para inteiros
		for (String s : separadoVirgula) {
			inteiros.add(Integer.parseInt(s));
		}

		// Lista de string para valor em hexadecimal
		List<String> listEmHex = new ArrayList<>();

		// Tranformar inteiros em valor hexadecimal
		for (Integer int1 : inteiros) {
			listEmHex.add(Integer.toHexString(int1));
		}

		// Criar matriz 4x43
		int[][] roundKey0 = new int[4][4];

		// Variavel para contage,
		int contatdor = 0;

		// Adicionar lista de hexadecimais na matriz
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				roundKey0[j][i] = inteiros.get(contatdor);
				// String.format("0x%s ", listEmHex.get(contatdor));
				System.out.println(Integer.toHexString(roundKey0[j][i]));
				contatdor++;
			}
			System.out.println(" ");
		}

		// Adicionar o roundKey0 ao keySchedule
		List<List<Integer>> keySchedule = new ArrayList<>();
		keySchedule.add(Arrays.asList(roundKey0[0][0], roundKey0[1][0], roundKey0[2][0], roundKey0[3][0]));
		keySchedule.add(Arrays.asList(roundKey0[0][1], roundKey0[1][1], roundKey0[2][1], roundKey0[3][1]));
		keySchedule.add(Arrays.asList(roundKey0[0][2], roundKey0[1][2], roundKey0[2][2], roundKey0[3][2]));
		keySchedule.add(Arrays.asList(roundKey0[0][3], roundKey0[1][3], roundKey0[2][3], roundKey0[3][3]));

		// Lista roundConstant
		List<List<Integer>> roundConstant = new ArrayList<>();
		roundConstant.add(Arrays.asList(0x01, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x02, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x04, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x08, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x10, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x20, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x40, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x80, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x1B, 0, 0, 0));
		roundConstant.add(Arrays.asList(0x36, 0, 0, 0));

		for (int i = 3; i <= 42; i++) {
			// Lista para nova chave
			List<Integer> newKey = new ArrayList<>();

			// Adiciona lista da ultima posição
			newKey.addAll(keySchedule.get(i));

			// Rotacionar
			Collections.rotate(newKey, 3);

			// Substituir palavra seguindo tabela S-Box
			newKey = SBox.substituicao(newKey);

			// XOR w e roundConstant
			for (int j = 0; j < newKey.size(); j++) {
				int xor = newKey.get(j) ^ roundConstant.get(retornaposicaoRoundConstant(i)).get(j);
				newKey.set(j, xor);
			}

			// XOR w e primeira palavra da roundKey anterior
			for (int h = 0; h < newKey.size(); h++) {
				int xor = newKey.get(h) ^ keySchedule.get(i - 3).get(h);
				newKey.set(h, xor);
			}

			// Adicionar nova chave a lista
			keySchedule.add(newKey);
		}

		return keySchedule;
	}

	public static void cifragem(String text, List<List<Integer>> roundKeys) {

		// Lista de string para valor em hexadecimal
		List<String> listEmHex = new ArrayList<>();
		
		char[] arrayChar = text.toCharArray();
		for (char c : arrayChar) {
			listEmHex.add(Integer.toHexString((int) c));
		}

		// Criar matriz 4x43
		int[][] roundKey0 = new int[4][4];

		// Variavel para contage,
		int contador = 0;

		// Adicionar lista de hexadecimais na matriz
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				roundKey0[j][i] = Integer.parseInt(String.valueOf(listEmHex.get(contador)), 16);
				// String.format("0x%s ", listEmHex.get(contatdor));
				System.out.println(roundKey0[j][i]);
				contador++;
			}
			System.out.println(" ");
		}
		
		System.out.println(Integer.toHexString(roundKeys.get(0).get(0)));
		System.out.println(Integer.toHexString(roundKeys.get(0).get(1)));
		System.out.println(Integer.toHexString(roundKeys.get(0).get(2)));
		System.out.println(Integer.toHexString(roundKeys.get(0).get(3)));
		
	}

}
