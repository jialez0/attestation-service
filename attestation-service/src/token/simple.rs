// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jwt::algorithm::openssl::PKeyWithDigest;
use jwt::{token::signed::SignWithKey, AlgorithmType, Header, Token};
use openssl::asn1::Asn1Time;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
};
use serde_json::{json, Value};

use crate::token::{AttestationTokenBroker, AttestationTokenConfig};

const ISSUER_NAME: &str = "CoCo-Attestation-Service";
const SIMPLE_KEY_ID: &str = "simple";

pub struct SimpleAttestationTokenBroker {
    config: AttestationTokenConfig,
    private_key: Rsa<Private>,
    public_key: Rsa<Public>,
    cert: X509,
}

impl SimpleAttestationTokenBroker {
    pub fn new(config: AttestationTokenConfig) -> Result<Self> {
        let private_key = Rsa::generate(2048)?;
        let public_key =
            Rsa::from_public_components(private_key.n().to_owned()?, private_key.e().to_owned()?)?;

        let mut x509_cert_builder = X509Builder::new()?;
        let mut x509_issuer_name = X509NameBuilder::new()?;
        x509_issuer_name.append_entry_by_text("CN", ISSUER_NAME)?;

        let cert_pubkey = PKey::public_key_from_pem(&public_key.public_key_to_pem()?)?;
        x509_cert_builder.set_version(2)?;
        x509_cert_builder.set_pubkey(&cert_pubkey)?;
        x509_cert_builder.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
        x509_cert_builder.set_issuer_name(&x509_issuer_name.build())?;
        x509_cert_builder.sign(
            PKey::from_rsa(private_key.clone())?.as_ref(),
            MessageDigest::sha384(),
        )?;
        let cert = x509_cert_builder.build();

        Ok(Self {
            config,
            private_key,
            public_key,
            cert,
        })
    }
}

impl AttestationTokenBroker for SimpleAttestationTokenBroker {
    fn issue(&self, custom_claims: Value) -> Result<String> {
        let rs384_private_key = PKeyWithDigest {
            digest: MessageDigest::sha384(),
            key: PKey::private_key_from_pem(&self.private_key.private_key_to_pem()?)?,
        };

        let header = Header {
            algorithm: AlgorithmType::Rs384,
            key_id: Some(SIMPLE_KEY_ID.to_string()),
            ..Default::default()
        };

        let mut claims = custom_claims.clone();
        claims["iss"] = Value::String(
            self.config
                .issuer_name
                .clone()
                .unwrap_or(ISSUER_NAME.to_string()),
        );
        claims["jwk"] = serde_json::from_str::<Value>(&self.pubkey_jwks()?)?["keys"][0].clone();

        let mut timer = time::OffsetDateTime::now_utc();
        timer = timer + time::Duration::minutes(1);
        claims["exp"] = Value::Number(timer.unix_timestamp().into());

        let token = Token::new(header, claims).sign_with_key(&rs384_private_key)?;
        Ok(token.as_str().to_string())
    }

    fn pubkey_jwks(&self) -> Result<String> {
        let jwk = json!({
            "kty": "RSA",
            "alg": "RS384",
            "n": URL_SAFE_NO_PAD.encode(self.public_key.n().to_vec()),
            "e": URL_SAFE_NO_PAD.encode(self.public_key.e().to_vec()),
            "kid": SIMPLE_KEY_ID,
            "x5c": vec![URL_SAFE_NO_PAD.encode(self.cert.to_der()?)],
        });
        let jwks = json!({
            "keys": vec![jwk],
        });

        Ok(serde_json::to_string(&jwks)?)
    }
}
