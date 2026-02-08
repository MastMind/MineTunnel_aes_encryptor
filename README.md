# MineTunnel_aes_encryptor
The ecnryption plugin for [MineTunnel](https://github.com/MastMind/MineTunnel "MineTunnel repo").
This is a basic implementation of AES128-CBC algorithm.

# Build and requirements
rustc 1.95.0-nightly or higher is recomended.

# How to use it
The result as `.so` file can be attached to MineTunnel as encryption plugin (More detailed [here](https://github.com/MastMind/MineTunnel "MineTunnel repo") chapter "Encryption").

# Format of encryption_params JSON

```
encryption_params : {
	"key": "00112233445566778899aabbccddeeff",
	"iv":  "00000000000000000000000000000000"
}
```
