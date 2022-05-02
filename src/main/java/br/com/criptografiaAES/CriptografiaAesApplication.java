package br.com.criptografiaAES;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class })
public class CriptografiaAesApplication {

	public static void main(String[] args) {
		SpringApplication.run(CriptografiaAesApplication.class, args);
	}

}
