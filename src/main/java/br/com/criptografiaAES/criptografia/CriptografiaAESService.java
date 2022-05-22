package br.com.criptografiaAES.criptografia;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

@Service
public class CriptografiaAESService {


	//Utilizado para comparar resultados
	public byte[] criptografarAPIJAVA(byte[] textoCriptografar, String nomeArquivoDestino) {
		try {

			byte[] chave = new byte[] {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P'};

			SecretKeySpec chaveSecreta = new SecretKeySpec(chave, "AES");

			Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");

			cifra.init(Cipher.ENCRYPT_MODE, chaveSecreta);

			byte[] criptografado = cifra.doFinal(textoCriptografar);

			// C:\Temp

			FileWriter arq = new FileWriter("C:\\Temp\\" + nomeArquivoDestino + ".txt");
			PrintWriter gravarArq = new PrintWriter(arq);

			String hex = new BigInteger(1, criptografado).toString(16);
			gravarArq.printf(hex);
			arq.close();

			return criptografado;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	//Utilizado para comparar resultados
	public String descriptografar(byte[] byteText) {
		try {

			byte[] chave = new byte[] {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P'};
			SecretKeySpec chaveSecreta = new SecretKeySpec(chave, "AES");

			Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");

			cifra.init(Cipher.DECRYPT_MODE, chaveSecreta);

			byte[] descriptografado = cifra.doFinal(byteText);
			
			return new String(descriptografado);
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}

	}

	// Retorna index para a lista RoundConstant
	private int retornaposicaoRodadasConstantes(int i) {
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

	//Converter string para hexadecimal
	private String toHex(String arg) throws UnsupportedEncodingException {
		return String.format("0x%x", new BigInteger(1, arg.getBytes("UTF-8")));
	}

	// Expansão da chave
	public List<List<Integer>> expansaoDaChave(String key) throws UnsupportedEncodingException {
		// Seperar a chave por virgula
		String[] sepradoPorVirgula = key.split(",");

		// Lista de inteiros
		List<Integer> inteiros = new ArrayList<>();

		// Transformar a lista de string para inteiros
		for (String s : sepradoPorVirgula) {
			boolean integerOrNot2 = s.matches("-?\\d+");
			
			if (integerOrNot2) {
				inteiros.add(Integer.decode(s));
			} else {
				inteiros.add(Integer.decode(toHex(s)));
			}
		}

		// Criar matriz 4x43
		int[][] chaveRodada0 = new int[4][4];

		// Variavel para contagem
		int counter = 0;

		// Adicionar lista de hexadecimais na matriz
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				chaveRodada0[j][i] = inteiros.get(counter);
				counter++;
			}
		}

		// Adicionar o roundKey0 ao keySchedule
		List<List<Integer>> matrizDasChaves = new ArrayList<>();
		matrizDasChaves.add(Arrays.asList(chaveRodada0[0][0], chaveRodada0[1][0], chaveRodada0[2][0], chaveRodada0[3][0]));
		matrizDasChaves.add(Arrays.asList(chaveRodada0[0][1], chaveRodada0[1][1], chaveRodada0[2][1], chaveRodada0[3][1]));
		matrizDasChaves.add(Arrays.asList(chaveRodada0[0][2], chaveRodada0[1][2], chaveRodada0[2][2], chaveRodada0[3][2]));
		matrizDasChaves.add(Arrays.asList(chaveRodada0[0][3], chaveRodada0[1][3], chaveRodada0[2][3], chaveRodada0[3][3]));

		// Lista roundConstant
		List<List<Integer>> matrizRodadasConstantes = new ArrayList<>();
		matrizRodadasConstantes.add(Arrays.asList(0x01, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x02, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x04, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x08, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x10, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x20, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x40, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x80, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x1B, 0, 0, 0));
		matrizRodadasConstantes.add(Arrays.asList(0x36, 0, 0, 0));

		for (int i = 3; i <= 42; i++) {
			// Lista para nova chave
			List<Integer> novaChave = new ArrayList<>();

			// Adiciona lista da ultima posição
			novaChave.addAll(matrizDasChaves.get(i));

			if ((i + 1) % 4 == 0) {
				// Rotacionar
				Collections.rotate(novaChave, 3);

				// Substituir palavra seguindo tabela S-Box
				novaChave = SBox.substituicao(novaChave);

				// XOR w e roundConstant
				for (int j = 0; j < novaChave.size(); j++) {
					int xor = novaChave.get(j) ^ matrizRodadasConstantes.get(retornaposicaoRodadasConstantes(i)).get(j);
					novaChave.set(j, xor);
				}
			}

			// XOR w e primeira palavra da roundKey anterior
			for (int h = 0; h < novaChave.size(); h++) {
				int xor = novaChave.get(h) ^ matrizDasChaves.get(i - 3).get(h);
				novaChave.set(h, xor);
			}

			// Adicionar nova chave a lista
			matrizDasChaves.add(novaChave);
		}

		return matrizDasChaves;
	}

	//Parte da multiplicação de galois
	private Integer galois(Integer r, Integer multiplicacao) {
		//Se um dos termos for zero retorna zero
		if (r == 0 || multiplicacao == 0) {
			return 0;
		} else {
			//Se r é igual a 1 retorna multiplicacao
			if (r == 1) {
				return multiplicacao;
			//Se multiplicacao é igual a 1 retorna r
			} else if (multiplicacao == 1) {
				return r;
			}
		}

		//Substitui na tabela L o valor r e a multiplicacao e soma 
		Integer resultado = TabelaL.substituicao(r) + TabelaL.substituicao(multiplicacao);

		//Se o resultado for maior que 0xFF retorna a subtituicao na Tabela E com o valor do resultado menos 0xFF
		if (resultado > 255) {
			return TabelaE.substituicao(resultado - 255);
		}

		//Substitui o resultado na Tabela E
		return TabelaE.substituicao(resultado);
	}


	//Incluir o preenchimento com base no PKCS#5
	private String preenhimento(List<String> s) {
		//Pega o último bloco
		String ultimo = s.get(s.size() -1);
		
		//Pega o valor que não está preenchido
		Integer valor = 16 - (ultimo.length() / 2);
		
		//Variável para colocar o preeenchimento
		String nova = "";
		
		//Enquanto i for menor que valor que não está preeenchido adiciona o número não preenchido
		for (int i = 0; i < valor; i++) {
			//Se for o último valor não adiciona virgula
			if (i == valor - 1) {
				nova += valor;
			} else {
				nova += valor + ",";
			}
		}
		return nova;
	}

	//Incluir preenchimento total
	private String novoPreenchimento() {
		//Valor do preenchimento
		Integer valor = 16;
		
		//Variável para colocar o preeenchimento
		String nova = "";
		
		//Enquanto i for menor que valor que não está preeenchido adiciona o número não preenchido
		for (int i = 0; i < valor; i++) {
			//Se for o último valor não adiciona virgula
			if (i == valor - 1) {
				nova += valor;
			} else {
				nova += valor + ",";
			}
		}
		return nova;
	}

	private String converterParaString(List<Integer> textInInteger) {
		//Variável para colocar resultado
		String p = "";
		
		//Percorrer lista de inteiros para converter para string
		for (Integer integer : textInInteger) {
			//Se inteiro for menor que 15 adicionar 0 junto
			if (integer <= 15) {
				p += String.format("%s", "0" + Integer.toHexString(integer));
			} else {
				p += String.format("%s", Integer.toHexString(integer));
			}

		}
		return p;
	}

	//Salvar reultado da criptografia em um arquivo na pasta Temp
	public void salvarResultado(String nomeArquivoDestino, String resultado) throws IOException {
		FileWriter arq = new FileWriter("C:\\Temp\\" + nomeArquivoDestino + ".txt");
		PrintWriter gravarArq = new PrintWriter(arq);

		gravarArq.printf(resultado);
		arq.close();
	}
	
	//Dividir string em blocos de 16
	private List<String> dividirStringEM16(String texto) {
		//Seperar por caracter
		String[] listaCaracteres = texto.split("(?<=\\G.{2})");
		
		//Variável para adicionar resultado
		List<String> listaResultado = new ArrayList<>();
		
		//Variável para adiconar resultado temporariamente
		String s = "";
		
		//Variável para contagem
		int contador = 0;
		
		//Percorrer lista de caracteres
		for (String string : listaCaracteres) {
			//Enquanto contador for menos que 15 adiciona na string temporária
			if (contador < 15) {
				//Adicionar caracter na string temporária
				s += string;
				//Adicionar no contador
				contador++;
			//Se o contador for igual a 15 adiciona o bloco de 16 caracteres na lista
			} else if (contador == 15) {
				//Adicionar caracter na string temporária
				s += string;
				//Adiciona string temporária na lista 
				listaResultado.add(s);  
				//Zera contador
				contador = 0;
				//Limpa string temporária
				s = "";
			}
		}
		//Se a string temporária não estiver vazia adiciona o resultado na lista
		if (s != "") {
			listaResultado.add(s);
		}
		
		return listaResultado;
	}
	
	private String converterParaHexadecimal(String texto) throws UnsupportedEncodingException {
		String stringHexadecimal = "";
		for (int i = 0; i < texto.length(); i++) {
			char s = texto.charAt(i);
			String string = String.valueOf(s);
			String hex = String.format("%x", new BigInteger(1, string.getBytes("UTF-8")));
			if (hex.length() <= 1) {
				hex =  String.format("0%s", hex);
			}
			stringHexadecimal += hex;
		}
		return stringHexadecimal;
	}
	
	//Criptogarfar AES/ECB/PKCS#5
	public String criptografar(String texto, List<List<Integer>> rodadasDasChaves)
			throws NumberFormatException, UnsupportedEncodingException {
		//Converter texto para hexadecimal
		texto.length();
		String textoHexadecimal = converterParaHexadecimal(texto);
		textoHexadecimal.length();
		//Dividir texto em blocos 
		List<String> blocos = dividirStringEM16(textoHexadecimal);
		
		//Resultado da criptografia
		String resultado = "";
		
		//Verificar preenchimento
		String preenchimento = preenhimento(blocos);
		
		//Percorrer blocos
		for (int i = 0; i < blocos.size(); i++) {
			
			//Se for o último bloco deve verificar preenchimento antes de criptografar
			if (i == blocos.size() - 1) {
				
				//Se o preenchimento for igual a zero deve adicionar um bloco inteiro de preenchimento (16)
				if (preenchimento == "") {
					//Criptografar bloco de texto
					resultado += converterParaString(criptografar(blocos.get(i), rodadasDasChaves, ""));
					
					//Criptografar preenchimento
					resultado += converterParaString(criptografar("", rodadasDasChaves, novoPreenchimento()));
				} else {
					resultado += converterParaString(criptografar(blocos.get(i), rodadasDasChaves, preenchimento));
				}

			} else {
				resultado += converterParaString(criptografar(blocos.get(i), rodadasDasChaves, ""));
			}
		}

		return resultado;
	}

	
	//Criptografar blocos
	private List<Integer> criptografar(String texto, List<List<Integer>> rodadasDasChaves, String preenchimento)
			throws NumberFormatException, UnsupportedEncodingException {

		// Lista de inteiros
		List<Integer> inteiros = new ArrayList<>();

		//Separar caracteres
		String[] separadoCadaCaracter = null;

		
		//Se texto for diferente de vazio então separa cada par de caracteres para converter para inteiro
		if (texto != "") {
			// Seperar texto por caracter
			separadoCadaCaracter = texto.split("(?<=\\G.{2})");

			// Transformar a lista de string para inteiros
			for (String s : separadoCadaCaracter) {
				inteiros.add(Integer.decode(String.format("0x%s", s)));
			}
		}

		//Se preenchimento for diferente de vazio então separa por virgula para converter para inteiro
		if (preenchimento != "") {
			// Seperar texto por caracter
			separadoCadaCaracter = preenchimento.split(",");

			// Transformar a lista de string para inteiros
			for (String s : separadoCadaCaracter) {
				inteiros.add(Integer.decode(s));
			}
		}
		
		//Matriz para aplicar passos
		List<Integer> matriz = new ArrayList<>();

		//Index da chave 
		int indexChave = 0;
		
		//Index do valor
		int index = 0;

		// AddRoundKey - Round 0
		for (int i = 0; i < inteiros.size(); i++) {
			int xor = inteiros.get(i) ^ rodadasDasChaves.get(indexChave).get(index);
			matriz.add(xor);
			
			//Se o valor do indice for igual a 3 deve começar a contagem por zero de novo e aumentar index da chave
			if (index != 0 && index % 3 == 0) {
				index = 0;
				indexChave++;
			} else {
				index++;
			}
		}

		//Percorrer 9 vezes 
		for (int i = 0; i < 10; i++) {
			
			// Subbytes
			matriz = SBox.substituicao(matriz);

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

			//Se for a última rodada apenas adiciona a chave e não faz o mix columns
			if (i == 9) {
				matriz.clear();

				// AddRoundKey
				for (int i1 = 0; i1 < matrizShiftRows.size(); i1++) {
					int xor = matrizShiftRows.get(i1) ^ rodadasDasChaves.get(indexChave).get(index);
					matriz.add(xor);
					if (index != 0 && index % 3 == 0) {
						index = 0;
						indexChave++;
					} else {
						index++;
					}
				}

			} else {

				// Mix Columns
				List<Integer> matrizMixColumns = new ArrayList<>();

				for (int i1 = 0; i1 < matrizShiftRows.size(); i1 += 4) {
					matrizMixColumns.add(galois(matrizShiftRows.get(i1), 2) ^ galois(matrizShiftRows.get(i1 + 1), 3)
							^ galois(matrizShiftRows.get(i1 + 2), 1) ^ galois(matrizShiftRows.get(i1 + 3), 1));
					matrizMixColumns.add(galois(matrizShiftRows.get(i1), 1) ^ galois(matrizShiftRows.get(i1 + 1), 2)
							^ galois(matrizShiftRows.get(i1 + 2), 3) ^ galois(matrizShiftRows.get(i1 + 3), 1));
					matrizMixColumns.add(galois(matrizShiftRows.get(i1), 1) ^ galois(matrizShiftRows.get(i1 + 1), 1)
							^ galois(matrizShiftRows.get(i1 + 2), 2) ^ galois(matrizShiftRows.get(i1 + 3), 3));
					matrizMixColumns.add(galois(matrizShiftRows.get(i1), 3) ^ galois(matrizShiftRows.get(i1 + 1), 1)
							^ galois(matrizShiftRows.get(i1 + 2), 1) ^ galois(matrizShiftRows.get(i1 + 3), 2));
				}

				matriz.clear();

				// AddRoundKey
				for (int i1 = 0; i1 < matrizMixColumns.size(); i1++) {
					int xor = matrizMixColumns.get(i1) ^ rodadasDasChaves.get(indexChave).get(index);
					matriz.add(xor);
					if (index != 0 && index % 3 == 0) {
						index = 0;
						indexChave++;
					} else {
						index++;
					}
				}

				matrizMixColumns.clear();
				matrizShiftRows.clear();

			}

		}
		return matriz;
	}

}