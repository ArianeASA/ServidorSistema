# Makefile

# Compila main.c (cria código-objeto ServidorSistema)
compile:
	gcc main.c -o ServidorSistema -lcrypto -lpthread

# Executa o ServidorSistema
run:
	./ServidorSistema

# Remove executável e códigos-objeto
clean:
	rm -f ServidorSistema *.o