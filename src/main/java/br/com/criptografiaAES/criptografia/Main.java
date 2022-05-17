package br.com.criptografiaAES.criptografia;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.List;

public class Main {

	public static void main(String[] args) throws UnsupportedEncodingException {
		//String chave = "20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248";
		String chave = "A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P";
		List<List<Integer>> roundKeys = CriptografiaAESService.keyExpansion(chave);
		List<Integer> t1 = CriptografiaAESService.encrypt("1234567891234567", roundKeys, 0);
		System.out.println("\nPrimaeira parte");
		for (Integer integer : t1) {
			System.out.println(String.format("0x%s ", Integer.toHexString(integer)) + " ");
		}
		//List<Integer> t2 = CriptografiaAESService.encrypt("16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16", roundKeys, 1);
		//System.out.println("\nSegunda parte");
		//for (Integer integer : t2) {
		//	System.out.println(String.format("0x%s ", Integer.toHexString(integer)) + " ");
		//}
		
		System.out.println("\n API JAVA");
		byte[] s = CriptografiaAESService.criptografar("1234567891234567".getBytes(), chave, "t");
		System.out.println(new BigInteger(1, s).toString(16));
		String p = CriptografiaAESService.decrypt(s, chave);
		System.out.println(p);
	}

}
