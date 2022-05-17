package br.com.criptografiaAES.criptografia;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
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

	public static byte[] criptografar(byte[] textoCriptografar, String chave, String nomeArquivoDestino) {
		try {

			byte[] keyValue = new byte[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
					'P' };

			SecretKeySpec key1 = new SecretKeySpec(keyValue, "AES");

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

	public static String decrypt(byte[] byteText, String chave) {
		try {

			byte[] keyValue = new byte[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
					'P' };
			SecretKeySpec key1 = new SecretKeySpec(keyValue, "AES");

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

	private static String asciiToHex(String asciiStr) {
	    char[] chars = asciiStr.toCharArray();
	    StringBuilder hex = new StringBuilder();
	    for (char ch : chars) {
	        hex.append(Integer.toHexString((int) ch));
	    }

	    return hex.toString();
	}
	
	// Expansão da chave
	public static List<List<Integer>> keyExpansion(String key) throws UnsupportedEncodingException {
		// Seperar a chave por virgula
		String[] commaSeparated = key.split(",");

		// Lista de inteiros
		List<Integer> integers = new ArrayList<>();

		// Transformar a lista de string para inteiros
		for (String s : commaSeparated) {
			integers.add(Integer.decode(toHex(s)));
		}

		// Criar matriz 4x43
		int[][] roundKey0 = new int[4][4];

		// Variavel para contagem
		int counter = 0;

		// Adicionar lista de hexadecimais na matriz
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				roundKey0[j][i] = integers.get(counter);
				counter++;
			}
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

	private static Integer galois(Integer r, Integer multiplicacao) {
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
			return TabelaE.substituicao(resultado - 255);
		}

		return TabelaE.substituicao(resultado);
	}

	public static String convertStringToHex(String str) {

        // display in uppercase
        //char[] chars = Hex.encodeHex(str.getBytes(StandardCharsets.UTF_8), false);

        // display in lowercase, default
        char[] chars = Hex.encodeHex(str.getBytes(StandardCharsets.UTF_8));

        return String.valueOf(chars);
    }
	
	public static List<Integer> encrypt(String text, List<List<Integer>> roundKeys, int t)
			throws NumberFormatException, UnsupportedEncodingException {
		int contador = 1;

		// Lista de inteiros
		List<Integer> textInInteger = new ArrayList<>();

		String[] separadoCadaCaracter = null;
		if (t == 0) {
			// Seperar texto por caracter
			separadoCadaCaracter = text.split("");

			// Transformar a lista de string para inteiros
			for (String s : separadoCadaCaracter) {
				textInInteger.add(Integer.decode(toHex(s)));
			}
		} else {
			// Seperar texto por caracter
			separadoCadaCaracter = text.split(",");

			// Transformar a lista de string para inteiros
			for (String s : separadoCadaCaracter) {
				textInInteger.add(Integer.decode(convertStringToHex(s)));
			}
		}

		List<Integer> matriz = new ArrayList<>();

		int variavelFora = 0;
		int index = 0;

		// AddRoundKey - Round 0
		for (int i = 0; i < textInInteger.size(); i++) {
			int xor = textInInteger.get(i) ^ roundKeys.get(variavelFora).get(index);
			matriz.add(xor);
			if (index != 0 && index % 3 == 0) {
				index = 0;
				variavelFora++;
			} else {
				index++;
			}
		}

		// System.out.println("\nRound keys");
		// for (Integer integer : matriz) {
		// System.out.println(String.format("0x%s ", Integer.toHexString(integer)) + "
		// ");
		// }

		// AddRoundeKey - Round 0
		// for (int h = 0; h < textInInteger.size(); h++) {
		// int xor = textInInteger.get(h) ^ roundkey0.get(h);
		// matriz.add(xor);
		// }

		for (int i = 0; i < 10; i++) {
			// Subbytes
			matriz = SBox.substituicao(matriz);

			// System.out.println("\nSubbytes");
			// for (Integer integer : matriz) {
			// System.out.println(String.format("0x%s ", Integer.toHexString(integer)) + "
			// ");
			// }

			// ShiftRows
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

			// System.out.println("\nMatriz ShiftRow");
			// for (Integer integer : matrizShiftRows) {
			// System.out.println(String.format("0x%s ", Integer.toHexString(integer)) + "
			// ");
			// }

			if (i == 9) {
				matriz.clear();

				// AddRoundKey
				for (int i1 = 0; i1 < matrizShiftRows.size(); i1++) {
					int xor = matrizShiftRows.get(i1) ^ roundKeys.get(variavelFora).get(index);
					matriz.add(xor);
					if (index != 0 && index % 3 == 0) {
						index = 0;
						variavelFora++;
					} else {
						index++;
					}
				}

			} else {

				// Mix Columns
				List<Integer> matrizEtapa4 = new ArrayList<>();

				contador = 0;
				for (int i1 = 0; i1 < matrizShiftRows.size(); i1 += 4) {
					matrizEtapa4.add(galois(matrizShiftRows.get(i1), 2) ^ galois(matrizShiftRows.get(i1 + 1), 3)
							^ galois(matrizShiftRows.get(i1 + 2), 1) ^ galois(matrizShiftRows.get(i1 + 3), 1));
					matrizEtapa4.add(galois(matrizShiftRows.get(i1), 1) ^ galois(matrizShiftRows.get(i1 + 1), 2)
							^ galois(matrizShiftRows.get(i1 + 2), 3) ^ galois(matrizShiftRows.get(i1 + 3), 1));
					matrizEtapa4.add(galois(matrizShiftRows.get(i1), 1) ^ galois(matrizShiftRows.get(i1 + 1), 1)
							^ galois(matrizShiftRows.get(i1 + 2), 2) ^ galois(matrizShiftRows.get(i1 + 3), 3));
					matrizEtapa4.add(galois(matrizShiftRows.get(i1), 3) ^ galois(matrizShiftRows.get(i1 + 1), 1)
							^ galois(matrizShiftRows.get(i1 + 2), 1) ^ galois(matrizShiftRows.get(i1 + 3), 2));
				}

				// System.out.println("\nMaxi columns");
				// for (Integer integer : matrizEtapa4) {
				// System.out.println(String.format("0x%s ", Integer.toHexString(integer)) + "
				// ");
				// }

				matriz.clear();

				// AddRoundKey
				for (int i1 = 0; i1 < matrizEtapa4.size(); i1++) {
					int xor = matrizEtapa4.get(i1) ^ roundKeys.get(variavelFora).get(index);
					matriz.add(xor);
					if (index != 0 && index % 3 == 0) {
						index = 0;
						variavelFora++;
					} else {
						index++;
					}
				}

				matrizEtapa4.clear();
				matrizShiftRows.clear();

			}

			// System.out.println("\nRound keys");
			// for (Integer integer : matriz) {
			// System.out.println(String.format("0x%s ", Integer.toHexString(integer)) + "
			// ");
			// }
		}
		return matriz;
	}

}