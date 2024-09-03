import {
  decryptAes256Gcm, deriveAes256GcmKeyFromEcdhP384Keys,
  generateEcdhP384Keys,
} from './utils';

export interface AuthtasticRedirectOpts {
    redirect_uri: string,
    return_uri: string,
}

export async function redirectToAuthtastic(opts: AuthtasticRedirectOpts) {
  const [pub_key, priv_key] = await generateEcdhP384Keys();

  localStorage.setItem('AUTHTASTIC_token_handoff_priv_key', priv_key);
  location.replace(`${opts.redirect_uri
  }?return_uri=${encodeURIComponent(opts.return_uri)
  }&pub_key=${encodeURIComponent(pub_key)
  }`);
}

export async function handleReturnFromAuthtastic() {
  const priv_key = localStorage.getItem('AUTHTASTIC_token_handoff_priv_key');
  if (priv_key === null) {
    throw new Error('No handoff key held in localStorage');
  }

  const urlSearchParams = new URLSearchParams(location.search);

  const encrypted_token = urlSearchParams.get('encrypted_token');
  const pub_key = urlSearchParams.get('pub_key');
  const iv = urlSearchParams.get('iv');

  if (encrypted_token === null || iv === null || pub_key === null) {
    throw new Error('request from Authtastic client does not have the "encrypted_token" or "pub_key" params');
  }

  const decryption_key = await deriveAes256GcmKeyFromEcdhP384Keys(pub_key, priv_key, 'decrypt');

  return decryptAes256Gcm(decryption_key, iv, encrypted_token);
}
