# Encrypt and Decrypt Objects with Fastly Compute

This project will encrypt objects before inserting them into the Fastly cache via the core cache API. This allows for storage of encrypted objects on Fastly disk (and memory) while decrypting them when delivering the objects to clients.

## Features

- Handles pre-encrypted objects or objects that need to be encrypted on the fly
- Matches on request URL path as objects in the /videos/encrypted/ folder are already encrypted on the server-side.