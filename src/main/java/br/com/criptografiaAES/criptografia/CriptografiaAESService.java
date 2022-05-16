package br.com.criptografiaAES.criptografia;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
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

	public static String toHex(String arg) throws UnsupportedEncodingException {
		return String.format("0x%x", new BigInteger(1, arg.getBytes("UTF-8")));
	}

	public static List<List<Integer>> expansaoChave(String chave) throws UnsupportedEncodingException {
		// Seperar a chave por virgula
		String[] separadoVirgula = chave.split(",");

		// Lista de inteiros
		List<Integer> inteiros = new ArrayList<>();

		// Transformar a lista de string para inteiros
		for (String s : separadoVirgula) {
			inteiros.add(Integer.decode(toHex(s)));
			// System.out.println(Integer.decode(toHex(s)));
		}

		// Criar matriz 4x43
		int[][] roundKey0 = new int[4][4];

		// Variavel para contage,
		int contatdor = 0;

		// Adicionar lista de hexadecimais na matriz
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				roundKey0[j][i] = inteiros.get(contatdor);
				// System.out.println(String.format("0x%s ",
				// Integer.toHexString(roundKey0[j][i])));
				contatdor++;
			}
			// System.out.println(" ");
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

			if ((i + 1) % 4 == 0) {
				// Rotacionar
				Collections.rotate(newKey, 3);

				// Substituir palavra seguindo tabela S-Box
				newKey = SBox.substituicao(newKey);

				// XOR w e roundConstant
				for (int j = 0; j < newKey.size(); j++) {
					int xor = newKey.get(j) ^ roundConstant.get(retornaposicaoRoundConstant(i)).get(j);
					newKey.set(j, xor);
				}
			}

			// XOR w e primeira palavra da roundKey anterior
			for (int h = 0; h < newKey.size(); h++) {
				int xor = newKey.get(h) ^ keySchedule.get(i - 3).get(h);
				newKey.set(h, xor);
			}

			// Adicionar nova chave a lista
			keySchedule.add(newKey);
		}

		// System.out.println("\n Rounds Key");
		// for (List<Integer> list : keySchedule) {
		// for (Integer int1 : list) {
		// System.out.println(String.format("0x%s ", Integer.toHexString(int1)) + " ");
		// }
		// System.out.println(" ");
		// }

		return keySchedule;
	}

	public static void adicionarNaLista(List<Integer> lista, List<Integer> valoresAAdicionar) {
		for (Integer hex : valoresAAdicionar) {
			lista.add(hex);
		}
	}
	
	//private static Integer validaZeroOuUm(Integer integer) {
	//	if (integer == 49) {
	//		
	//	}
	//}

	private static Integer validarValorMáximo(Integer shiftRow, Integer multiplicacao) {
		if (shiftRow == 1) {
			return TabelaL.substituicao(multiplicacao);
		}
		if (shiftRow == 0) {
			return 0;
		}
		if (TabelaL.substituicao(multiplicacao) == 0) {
			return 0;
		}
		Integer soma = shiftRow + TabelaL.substituicao(multiplicacao);
		if (soma > 255) {
			return 255;
		}	
		return soma;
	}
	
	private static Integer validar0e1(Integer r1, Integer multiplicacao) {
		Integer p1 = validarValorMáximo(r1, multiplicacao);
		Integer soma = TabelaE.substituicao(p1);
		if (soma == 1) {
			return p1;
		}
		return soma;
	}
	
	private static Integer teste(Integer r, Integer multiplicacao) {
		if (r == 0 || multiplicacao == 0) {
			return 0;
		} else {
			if (r == 1) {
				return multiplicacao;
			} else if (multiplicacao == 1) {
				return r;
			}
		}
		
		Integer resultado = TabelaL.substituicao(r) + TabelaL.substituicao(multiplicacao);
		
		if (resultado > 255) {
			return 255;
		}
		
		return TabelaE.substituicao(resultado);
	}
	
	public static void cifragem(String text, List<List<Integer>> roundKeys) throws NumberFormatException, UnsupportedEncodingException {
		int contador = 1;

		// Seperar texto por caracter
		String[] separadoCadaCaracter = text.split("");

		// Lista de inteiros
		List<Integer> textInInteger = new ArrayList<>();

		// Transformar a lista de string para inteiros
		for (String s : separadoCadaCaracter) {
			textInInteger.add(Integer.decode(toHex(s)));
		}

		// Gravar roundKeys em lista para gerenciar melhor
		List<Integer> roundkey0 = new ArrayList<>();
		List<Integer> roundkey1 = new ArrayList<>();
		List<Integer> roundkey2 = new ArrayList<>();
		List<Integer> roundkey3 = new ArrayList<>();
		List<Integer> roundkey4 = new ArrayList<>();
		List<Integer> roundkey5 = new ArrayList<>();
		List<Integer> roundkey6 = new ArrayList<>();
		List<Integer> roundkey7 = new ArrayList<>();
		List<Integer> roundkey8 = new ArrayList<>();
		List<Integer> roundkey9 = new ArrayList<>();
		List<Integer> roundkey10 = new ArrayList<>();

		// Adicionar roundkeys na sua respectiva lista
		for (List<Integer> list : roundKeys) {
			if (contador >= 1 && contador <= 4) {
				adicionarNaLista(roundkey0, list);
			}
			if (contador >= 5 && contador <= 8) {
				adicionarNaLista(roundkey1, list);
			}
			if (contador >= 9 && contador <= 12) {
				adicionarNaLista(roundkey2, list);
			}
			if (contador >= 13 && contador <= 16) {
				adicionarNaLista(roundkey3, list);
			}
			if (contador >= 17 && contador <= 20) {
				adicionarNaLista(roundkey4, list);
			}
			if (contador >= 21 && contador <= 24) {
				adicionarNaLista(roundkey5, list);
			}
			if (contador >= 25 && contador <= 28) {
				adicionarNaLista(roundkey6, list);
			}
			if (contador >= 29 && contador <= 32) {
				adicionarNaLista(roundkey7, list);
			}
			if (contador >= 33 && contador <= 36) {
				adicionarNaLista(roundkey8, list);
			}
			if (contador >= 37 && contador <= 40) {
				adicionarNaLista(roundkey9, list);
			}
			if (contador >= 41 && contador <= 44) {
				adicionarNaLista(roundkey10, list);
			}
			contador++;
		}
		
		List<Integer> matriz = new ArrayList<>();

		//AddRoundeKey - Round 0
		for (int h = 0; h < textInInteger.size(); h++) {
			int xor = textInInteger.get(h) ^ roundkey0.get(h);
			matriz.add(xor);
		}
		
		//Subbytes
		matriz = SBox.substituicao(matriz);
		
		//ShiftRows
		List<Integer> matrizShiftRows = new ArrayList<>();
		
		matrizShiftRows.add(matriz.get(0));
		matrizShiftRows.add(matriz.get(5));
		matrizShiftRows.add(matriz.get(10));
		matrizShiftRows.add(matriz.get(15));
		matrizShiftRows.add(matriz.get(4));
		matrizShiftRows.add(matriz.get(9));
		matrizShiftRows.add(matriz.get(14));
		matrizShiftRows.add(matriz.get(3));
		matrizShiftRows.add(matriz.get(8));
		matrizShiftRows.add(matriz.get(13));
		matrizShiftRows.add(matriz.get(2));
		matrizShiftRows.add(matriz.get(7));
		matrizShiftRows.add(matriz.get(12));
		matrizShiftRows.add(matriz.get(1));
		matrizShiftRows.add(matriz.get(6));
		matrizShiftRows.add(matriz.get(11));
		
		
		//Mix Columns
		List<Integer> matrizEtapa4 = new ArrayList<>();
		
		for (Integer integer : matrizShiftRows) {
			matrizEtapa4.add(TabelaL.substituicao(integer));
		}
		
		contador = 0;
		int b1 = 0;
		int b2 = 0;
		int b3 = 0;
		int b4 = 0;
		
		int b5 = 0;
		int b6 = 0;
		int b7 = 0;
		int b8 = 0;

		int b9 = 0;
		int b10 = 0;
		int b11 = 0;
		int b12 = 0;

		int b13 = 0;
		int b14 = 0;
		int b15 = 0;
		int b16 = 0;

		b1 = TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(0), 2)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(1), 3)) ^ TabelaE.substituicao(matrizEtapa4.get(2)) ^ TabelaE.substituicao(matrizEtapa4.get(3));
		b2 = TabelaE.substituicao(matrizEtapa4.get(0)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(1), 2)) ^ TabelaE.substituicao(validarValorMáximo( matrizEtapa4.get(2), 3)) ^ TabelaE.substituicao(matrizEtapa4.get(3));
		b3 = TabelaE.substituicao(matrizEtapa4.get(0)) ^ TabelaE.substituicao(matrizEtapa4.get(1)) ^ TabelaE.substituicao(validarValorMáximo( matrizEtapa4.get(2), 2)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(3), 3));
		b4 = TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(0), 3)) ^ TabelaE.substituicao(matrizEtapa4.get(1)) ^ TabelaE.substituicao(matrizEtapa4.get(2)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(3), 2));
			
		b5 = TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(4), 2)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(5) , 3)) ^ TabelaE.substituicao(matrizEtapa4.get(6)) ^ TabelaE.substituicao(matrizEtapa4.get(7));
		b6 = TabelaE.substituicao(matrizEtapa4.get(4)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(5), 2)) ^ TabelaE.substituicao(validarValorMáximo( matrizEtapa4.get(6), 3)) ^ TabelaE.substituicao(matrizEtapa4.get(7));
		b7 = TabelaE.substituicao(matrizEtapa4.get(4)) ^ TabelaE.substituicao(matrizEtapa4.get(5)) ^ TabelaE.substituicao(validarValorMáximo( matrizEtapa4.get(6), 2)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(7), 3));
		b8 = TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(4), 3)) ^ TabelaE.substituicao(matrizEtapa4.get(5)) ^ TabelaE.substituicao(matrizEtapa4.get(2)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(3), 2));
		
		b9 = TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(8), 2)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(9), 3)) ^ TabelaE.substituicao(matrizEtapa4.get(10)) ^ TabelaE.substituicao(matrizEtapa4.get(11));
		b10 = TabelaE.substituicao(matrizEtapa4.get(8)) ^ 255 ^ TabelaE.substituicao(validarValorMáximo( matrizEtapa4.get(10), 3)) ^ TabelaE.substituicao(matrizEtapa4.get(11));
		b11 = TabelaE.substituicao(matrizEtapa4.get(8)) ^ TabelaE.substituicao(matrizEtapa4.get(9)) ^ TabelaE.substituicao(validarValorMáximo( matrizEtapa4.get(10), 2)) ^ TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(11), 3));
		b12 = TabelaE.substituicao(validarValorMáximo(matrizEtapa4.get(8), 3)) ^ TabelaE.substituicao(matrizEtapa4.get(9)) ^ TabelaE.substituicao(matrizEtapa4.get(10)) ^ 255;
		
		b13 = validar0e1(matrizEtapa4.get(12), 2) ^ validar0e1(matrizEtapa4.get(13), 3) ^ TabelaE.substituicao(matrizEtapa4.get(14)) ^ TabelaE.substituicao(matrizEtapa4.get(15));
		b14 = TabelaE.substituicao(matrizEtapa4.get(12)) ^ validar0e1(matrizEtapa4.get(13), 2) ^ validar0e1(matrizEtapa4.get(14), 3) ^ TabelaE.substituicao(matrizEtapa4.get(15));
		b15 = TabelaE.substituicao(matrizEtapa4.get(12)) ^ TabelaE.substituicao(matrizEtapa4.get(13)) ^ validar0e1(matrizEtapa4.get(14), 2) ^ validar0e1(matrizEtapa4.get(15), 3);
		b16 = validar0e1(matrizEtapa4.get(12), 3) ^ TabelaE.substituicao(matrizEtapa4.get(13)) ^ TabelaE.substituicao(matrizEtapa4.get(14)) ^ validar0e1(matrizEtapa4.get(15), 2);
		
		Integer t = teste(matrizShiftRows.get(0), 2) ^ teste(matrizShiftRows.get(1), 3) ^ teste(matrizShiftRows.get(2), 1) ^ teste(matrizShiftRows.get(3), 1); 
		Integer t1 = teste(matrizShiftRows.get(0), 1) ^ teste(matrizShiftRows.get(1), 2) ^ teste(matrizShiftRows.get(2), 3) ^ teste(matrizShiftRows.get(3), 1); 
		Integer t2 = teste(matrizShiftRows.get(0), 1) ^ teste(matrizShiftRows.get(1), 1) ^ teste(matrizShiftRows.get(2), 2) ^ teste(matrizShiftRows.get(3), 3); 
		Integer t3 = teste(matrizShiftRows.get(0), 3) ^ teste(matrizShiftRows.get(1), 1) ^ teste(matrizShiftRows.get(2), 1) ^ teste(matrizShiftRows.get(3), 2); 
		
		Integer t4 = teste(matrizShiftRows.get(4), 2) ^ teste(matrizShiftRows.get(5), 3) ^ teste(matrizShiftRows.get(6), 1) ^ teste(matrizShiftRows.get(7), 1); 
		Integer t5 = teste(matrizShiftRows.get(4), 1) ^ teste(matrizShiftRows.get(5), 2) ^ teste(matrizShiftRows.get(6), 3) ^ teste(matrizShiftRows.get(7), 1); 
		Integer t6 = teste(matrizShiftRows.get(4), 1) ^ teste(matrizShiftRows.get(5), 1) ^ teste(matrizShiftRows.get(6), 2) ^ teste(matrizShiftRows.get(7), 3); 
		Integer t7 = teste(matrizShiftRows.get(4), 3) ^ teste(matrizShiftRows.get(5), 1) ^ teste(matrizShiftRows.get(6), 1) ^ teste(matrizShiftRows.get(7), 2); 
		
		Integer t8 = teste(matrizShiftRows.get(8), 2) ^ teste(matrizShiftRows.get(9), 3) ^ teste(matrizShiftRows.get(10), 1) ^ teste(matrizShiftRows.get(11), 1); 
		Integer t9 = teste(matrizShiftRows.get(8), 1) ^ teste(matrizShiftRows.get(9), 2) ^ teste(matrizShiftRows.get(10), 3) ^ teste(matrizShiftRows.get(11), 1); 
		Integer t10 = teste(matrizShiftRows.get(8), 1) ^ teste(matrizShiftRows.get(9), 1) ^ teste(matrizShiftRows.get(10), 2) ^ teste(matrizShiftRows.get(11), 3); 
		Integer t11 = teste(matrizShiftRows.get(8), 3) ^ teste(matrizShiftRows.get(9), 1) ^ teste(matrizShiftRows.get(10), 1) ^ teste(matrizShiftRows.get(11), 2); 
		
		Integer t12 = teste(matrizShiftRows.get(12), 2) ^ teste(matrizShiftRows.get(13), 3) ^ teste(matrizShiftRows.get(14), 1) ^ teste(matrizShiftRows.get(15), 1); 
		Integer t13 = teste(matrizShiftRows.get(12), 1) ^ teste(matrizShiftRows.get(13), 2) ^ teste(matrizShiftRows.get(14), 3) ^ teste(matrizShiftRows.get(15), 1); 
		Integer t14 = teste(matrizShiftRows.get(12), 1) ^ teste(matrizShiftRows.get(13), 1) ^ teste(matrizShiftRows.get(14), 2) ^ teste(matrizShiftRows.get(15), 3); 
		Integer t15 = teste(matrizShiftRows.get(12), 3) ^ teste(matrizShiftRows.get(13), 1) ^ teste(matrizShiftRows.get(14), 1) ^ teste(matrizShiftRows.get(15), 2); 
		
		System.out.println("\n");
		System.out.println(String.format("0x%s ", Integer.toHexString(b1)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b2)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b3)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b4)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b5)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b6)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b7)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b8)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b9)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b10)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b11)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b12)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b13)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b14)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b15)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(b16)) + " ");
		System.out.println("\n");
		System.out.println(String.format("0x%s ", Integer.toHexString(t)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t1)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t2)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t3)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t4)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t5)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t6)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t7)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t8)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t9)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t10)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t11)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t12)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t13)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t14)) + " ");
		System.out.println(String.format("0x%s ", Integer.toHexString(t15)) + " ");
	}

}
