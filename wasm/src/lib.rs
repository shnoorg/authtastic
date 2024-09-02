use wasm_bindgen::prelude::*;

use argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};

struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = Argon2<'static>;
}

#[wasm_bindgen]
pub struct RegistrationStartResult {
    state: Vec<u8>,
    message: Vec<u8>,
}

#[wasm_bindgen]
impl RegistrationStartResult {
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<u8> {
        self.state.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}

#[wasm_bindgen]
pub fn registration_start(password: String) -> Result<RegistrationStartResult, String> {
    let mut rng = OsRng;
    match ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes()) {
        Ok(start) => Ok(RegistrationStartResult {
            state: start.state.serialize().to_vec(),
            message: start.message.serialize().to_vec(),
        }),
        Err(err) => return Err(err.to_string()),
    }
}

#[wasm_bindgen]
pub fn registration_finish(
    password: String,
    client_start: Vec<u8>,
    server_start: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let client_start = match ClientRegistration::<DefaultCipherSuite>::deserialize(&client_start) {
        Ok(s) => s,
        Err(err) => return Err(err.to_string()),
    };

    let mut rng = OsRng;

    match client_start.finish(
        &mut rng,
        password.as_bytes(),
        RegistrationResponse::deserialize(&server_start).unwrap(),
        ClientRegistrationFinishParameters::default(),
    ) {
        Ok(finish) => Ok(finish.message.serialize().to_vec()),
        Err(err) => Err(err.to_string()),
    }
}

#[wasm_bindgen]
pub struct LoginStartResult {
    state: Vec<u8>,
    message: Vec<u8>,
}

#[wasm_bindgen]
impl LoginStartResult {
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<u8> {
        self.state.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}

#[wasm_bindgen]
pub fn login_start(password: String) -> Result<LoginStartResult, String> {
    let mut rng = OsRng;

    match ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes()) {
        Ok(login) => Ok(LoginStartResult {
            state: login.state.serialize().to_vec(),
            message: login.message.serialize().to_vec(),
        }),
        Err(err) => return Err(err.to_string()),
    }
}

#[wasm_bindgen]
pub struct LoginFinishResult {
    message: Vec<u8>,
    session_key: Vec<u8>,
}

#[wasm_bindgen]
impl LoginFinishResult {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn session_key(&self) -> Vec<u8> {
        self.session_key.clone()
    }
}

#[wasm_bindgen]
pub fn login_finish(
    password: String,
    client_start: Vec<u8>,
    server_start: Vec<u8>,
) -> Result<LoginFinishResult, String> {
    let client_login = match ClientLogin::<DefaultCipherSuite>::deserialize(&client_start) {
        Ok(l) => l,
        Err(err) => return Err(err.to_string()),
    };

    let server_start = match CredentialResponse::deserialize(&server_start) {
        Ok(s) => s,
        Err(err) => return Err(err.to_string()),
    };

    match client_login.finish(
        password.as_bytes(),
        server_start,
        ClientLoginFinishParameters::default(),
    ) {
        Ok(finish) => Ok(LoginFinishResult {
            message: finish.message.serialize().to_vec(),
            session_key: finish.session_key.to_vec(),
        }),
        Err(err) => return Err(err.to_string()),
    }
}
