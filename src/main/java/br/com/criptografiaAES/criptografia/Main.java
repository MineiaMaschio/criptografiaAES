package br.com.criptografiaAES.criptografia;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.List;

public class Main {

	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static void main(String[] args) throws UnsupportedEncodingException {
		//String chave = "20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248";
		String chave = "A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P";
		List<List<Integer>> roundKeys = CriptografiaAESService.keyExpansion(chave);
		String resultado = CriptografiaAESService.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ", roundKeys);
		System.out.println("\n Nossa api");
		System.out.println(resultado);
		
		System.out.println("\n API JAVA");
		byte[] s = CriptografiaAESService.criptografar("ABCDEFGHIJK".getBytes(), chave, "t");
		System.out.println(new BigInteger(1, s).toString(16));
		String p = CriptografiaAESService.decrypt(hexStringToByteArray(resultado), chave);
		System.out.println(p);
	}

}
