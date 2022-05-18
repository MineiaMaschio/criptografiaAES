package br.com.criptografiaAES.criptografia;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class CriptografiaAESController {

	@Autowired
	private CriptografiaAESService service;

	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	@RequestMapping(method = RequestMethod.POST, value = "/criptografar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseStatus criptografar(@RequestPart("file") MultipartFile file, @RequestParam String chave,
			@RequestParam String nomeDestino) throws IOException {
		String content = new String(file.getBytes(), "ASCII");
		List<List<Integer>> roundKeys = CriptografiaAESService.keyExpansion(chave);
		String resultado = service.encrypt(content, roundKeys);
		
		byte[] encrypt = service.criptografar(content.getBytes(), chave, nomeDestino);
		String hex = new BigInteger(1, encrypt).toString(16);

		System.out.println("\n");
		System.out.println("1.1 Conteudo do texto cifrado API JAVA: " + hex);
		System.out.println("1.2 Conteudo do texto cifrado API NOSS: " + resultado);
		
		System.out.println("\n");
		String p = CriptografiaAESService.decrypt(encrypt, chave);
		System.out.println("2.1 Conteudo do texto decifrado API JAVA: " +p);

		p = CriptografiaAESService.decrypt(hexStringToByteArray(resultado), chave);
		System.out.println("2.1 Conteudo do texto decifrado API NOSS: " +p);
		
		return null;
	}

}
