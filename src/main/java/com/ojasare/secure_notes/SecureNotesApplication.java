package com.ojasare.secure_notes;

import com.ojasare.secure_notes.security.jwt.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class SecureNotesApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecureNotesApplication.class, args);
	}

}
