package br.com.criptografiaAES.criptografia;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

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

	@RequestMapping(method = RequestMethod.POST, value = "/criptografar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseStatus criptografar(@RequestPart("file") MultipartFile file, @RequestParam String chave,
			@RequestParam String nomeDestino) throws IOException {
		String content = new String(file.getBytes(), StandardCharsets.UTF_8);
		byte[] encrypt = service.criptografar(content.getBytes(), chave, nomeDestino);
		String hex = new BigInteger(1, encrypt).toString(16);

		System.out.println("1.1 Conteudo do texto cifrado: " + hex);
		System.out.println("1.2 Extensão do texto cifrado: " + encrypt.length);

		String decrypt = service.decrypt(encrypt, chave);
		System.out.println("Descriptogrifa: " + decrypt);
		return null;
	}

}
