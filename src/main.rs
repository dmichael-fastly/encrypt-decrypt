//! Default Compute template program.

use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use aes_wasm::aes256cbc;
use hex;
use std::time::Instant;
use fastly::cache::core::{CacheKey, Transaction};
use std::time::Duration;
use std::io::Write;
use bytes::Bytes;
use fastly::secret_store::{LookupError, SecretStore};

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    // Log service version
    println!(
        "FASTLY_SERVICE_VERSION: {}",
        std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new())
    );

    // Filter request methods...
    match req.get_method() {
        // Block requests with unexpected methods
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD, PURGE")
                .with_body_text_plain("This method is not allowed\n"))
        }

        // Let any other requests through
        _ => (),
    };

    // TODO: Respond with 405 to range requests

    // First let's check if this object is in Fastly cache. The cache key is the URL
    let req_clone = req.clone_without_body();
    let cache_key = req_clone.get_path();
    println!("Processing request for path {}", cache_key);

    // Check cache - Start

    let mut source = "cache".to_string();

    let key: [u8; 32] = read_hex_config("key")?;
    let iv: [u8; 16] = read_hex_config("iv")?;

    const TTL: Duration = Duration::from_secs(3600);
    // perform the lookup
    let lookup_tx = Transaction::lookup(CacheKey::copy_from_slice(cache_key.to_string().as_bytes()))
        .execute()
        .unwrap();
    let (body, content_type) = if let Some(found) = lookup_tx.found() {
        // a cached item was found
        println!("Object found in cache");
        let encoded_full_body = found.to_stream().unwrap();
        (encoded_full_body.into_bytes(), String::from_utf8(found.user_metadata().to_vec()).unwrap())
    } else if lookup_tx.must_insert() || lookup_tx.must_insert_or_update() {
        // a cached item was not found, and we've been chosen to insert it
        println!("Object NOT found in cache");

        // Load the data from the origin
        let mut response = req.send("video_origin")?;
        if response.get_status() != 200 {
            return Ok(response);
        }
        // Set the "source" to "origin" as we need to get the data from the origin
        source = "origin".to_string();

        // Prepare to insert the object with surrogate keys
        // Check if there are some surrogate keys coming back from the origin as we want to include those as well
        let mut surrogate_keys =
            if let Some(value) = response.get_header_str("surrogate-key") {
                value.split(' ').map(|k| k.to_string()).collect()
            } else {
                vec![]
            };
        // Add the cache key as a surrogate key
        surrogate_keys.push(cache_key.to_string());
        surrogate_keys.push("all".to_owned());

        let content_type: String = response.get_header_str(header::CONTENT_TYPE).unwrap_or("").to_string();

        let mut insert = lookup_tx
        .insert(TTL)
        .surrogate_keys(
            surrogate_keys
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
        .user_metadata(Bytes::from(content_type.to_string()));
        // We store the content-type in user_metadata to return later

        // Files in the /videos/encrypted folder are already encypted. Otherwise we need to encrypt on the fly
        match cache_key.to_string() {
            path if path.starts_with("/videos/encrypted/") => {
                println!("Object is already encrypted at origin");
                // If the response from origin has a known length then provide it for the insert
                if let Some(known_length) = response.get_content_length() {
                    insert = insert.known_length(known_length as u64);
                };
                let mut writer = insert.execute().unwrap();
                let encoded_full_body = response.take_body_bytes();
                writer.write_all(&encoded_full_body).unwrap();
                writer.finish().unwrap();
                println!("Wrote already encrypted object to cache");
                (encoded_full_body, content_type.to_string())
            }
            _ => {
                println!("Object is NOT encrypted at origin");
                // If the response from origin has a known length then provide it for the insert
                // Since we're encrypting chunks as we go we don't know the full length yet
                // if let Some(known_length) = response.get_content_length() {
                //     insert = insert.known_length(known_length as u64);
                // };

                let mut writer = insert.execute().unwrap();
                let now = Instant::now();
                let full_body = response.take_body_bytes();
                let encoded_full_body = aes256cbc::encrypt(&full_body, &key, iv);
                writer.write_all(&encoded_full_body).unwrap();
                println!("{:?} to encrypt", now.elapsed());
                println!("vCPU = {} after encryption", fastly::compute_runtime::elapsed_vcpu_ms().unwrap());

                writer.finish().unwrap();
                println!("Wrote newly encrypted object to cache");
                (encoded_full_body, content_type.to_string())
            }
        }
    } else {
        unreachable!()
    };

    let now = Instant::now();
    let decoded_body = aes256cbc::decrypt(body, &key, iv)?;
    println!("vCPU = {} after decryption", fastly::compute_runtime::elapsed_vcpu_ms().unwrap());
    println!("{:?} to decrypt", now.elapsed());

    return Ok(Response::from_status(StatusCode::OK)
    .with_header(header::CACHE_CONTROL, "max-age=604800, stale-while-revalidate=86400")
    .with_header(header::CONTENT_TYPE, content_type)    
    .with_header("source", source)
    .with_body(decoded_body));

}

pub fn read_hex_config<const N: usize>(key: &str) -> Result<[u8; N], Error> {
    // read the config store value

    let store = SecretStore::open("encrypt-decrypt")?;
    let value = store
        .get(key)
        .ok_or_else(|| LookupError::InvalidSecretName(key.to_string()))?
        .plaintext()
        .to_vec();

    // decode the hex value into a byte vector
    let decoded = hex::decode(value)
        .map_err(|e| Error::msg(format!("Error decoding base64: {e}")))?;

    // convert the byte vector into a fixed size array
    let result: [u8; N] = decoded[..N]
        .try_into()
        .map_err(|e| Error::msg(format!("Unexpected config store value: {e} length")))?;

    Ok(result)
}
