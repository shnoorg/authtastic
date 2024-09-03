import init_authtastic, {
  registration_start, registration_finish, login_start, login_finish,
} from '@authtastic/wasm';
import { deriveAes256GcmKeyFromEcdhP384Keys, encryptAes256Gcm, generateEcdhP384Keys } from './utils';

export interface AuthtasticClientRedirectOpts {
  referer_pub_key?: string,
  referer_return_uri?: string,
}

export interface AuthtasticClientOpts {
    url: string,
    // defaults to 'v1',
    api_version?: 'v1',

    // defaults to 3
    init_retry_count?: number,
    // defaults to 500ms
    init_retry_timeout?: number,

    // for configuring redirect
    redirect_opts?: AuthtasticClientRedirectOpts
}

export class AuthtasticClient {
  opts: AuthtasticClientOpts;

  #is_ready: boolean;

  #init_retries: number;

  #token: null | string;

  constructor(opts: AuthtasticClientOpts) {
    this.#is_ready = false;
    init_authtastic().then(() => {
      this.#is_ready = true;
    });

    this.#init_retries = 0;

    this.#token = null;

    this.opts = {
      api_version: 'v1',
      ...opts,
    };
  }

  #checkIsReady(cb: () => void) {
    if (this.#is_ready) return true;

    if (this.#init_retries < (this.opts.init_retry_count ?? 3)) {
      setTimeout(() => {
        cb();
      }, this.opts.init_retry_timeout ?? 500);

      return false;
    }

    throw new Error('WASM Module Failed to initialize');
  }

  async register(username: string, password: string) {
    if (!this.#checkIsReady(() => this.register(username, password))) {
      return;
    }

    const client_start = registration_start(password);

    const server_start = await fetch(`${this.opts.url}/api/${this.opts.api_version}/registration_start`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        username,
        client_start: [...client_start.message],
      }),
    });

    if (server_start.ok) {
      const blob = await server_start.blob();
      const server_start_bytes = await blob.arrayBuffer();
      const client_finish = registration_finish(
        password,
        client_start.state,
        new Uint8Array(server_start_bytes),
      );

      await fetch(`${this.opts.url}/api/${this.opts.api_version}/registration_finish`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          username,
          client_finish: [...client_finish],
        }),
      });
    }
  }

  async login(username: string, password: string) {
    if (!this.#checkIsReady(() => this.login(username, password))) {
      return;
    }

    const client_start = login_start(password);

    const server_start = await fetch(`${this.opts.url}/api/${this.opts.api_version}/login_start`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        username,
        client_start: [...client_start.message],
      }),
    });

    const blob = await server_start.blob();
    const server_start_bytes = await blob.arrayBuffer();

    const client_finish = login_finish(
      password,
      client_start.state,
      new Uint8Array(server_start_bytes),
    );

    const token = await fetch(`${this.opts.url}/api/${this.opts.api_version}/login_finish`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        username,
        client_finish: [...client_finish.message],
        session_key: [...client_finish.session_key],
      }),
    });

    this.#token = await token.text();
  }

  async redirect() {
    if (!this.opts.redirect_opts) {
      throw new Error('Cannot redirect without options configured.');
    }

    if (!this.#token) {
      throw new Error('No token to redirect with.');
    }

    const [pub_key, priv_key] = await generateEcdhP384Keys();

    const encryption_key = await deriveAes256GcmKeyFromEcdhP384Keys(
      this.opts.redirect_opts.referer_pub_key,
      priv_key,
      'encrypt',
    );

    const [encrypted_token, iv] = await encryptAes256Gcm(encryption_key, this.#token);

    location.replace(`${this.opts.redirect_opts.referer_return_uri
    }?pub_key=${encodeURIComponent(pub_key)
    }&iv=${encodeURIComponent(iv)
    }&encrypted_token=${encodeURIComponent(encrypted_token)}`);
  }

  get token() {
    return this.#token;
  }
}
