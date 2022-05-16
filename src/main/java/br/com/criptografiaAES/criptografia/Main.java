package br.com.criptografiaAES.criptografia;

import java.io.UnsupportedEncodingException;
import java.util.List;

public class Main {

	public static void main(String[] args) throws UnsupportedEncodingException {
		//String chave = "20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248";
		String chave = "A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P";
		List<List<Integer>> roundKeys = CriptografiaAESService.expansaoChave(chave);
		CriptografiaAESService.cifragem("DESENVOLVIMENTO!", roundKeys);
	}

}
