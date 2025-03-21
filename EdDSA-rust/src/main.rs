use rand::rngs::OsRng;
use ed25519_dalek::{SigningKey, Signature, Signer, Verifier, VerifyingKey};

fn main() {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    let message: &[u8] = b"This is a random message";

    let signature: Signature = signing_key.sign(message);

    println!("Signature: {:?}", signature);

    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let verified: bool = verifying_key.verify(message, &signature).is_ok();

    println!("Verified: {}", verified);
}