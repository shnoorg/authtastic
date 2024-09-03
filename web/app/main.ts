/* eslint-disable no-param-reassign */
import { AuthtasticClient, redirectToAuthtastic, handleReturnFromAuthtastic } from '../src/index';

const simulate_redirect_button = document.getElementById('simulate-redirect') as HTMLButtonElement;
const token_el = document.getElementById('token') as HTMLParagraphElement;
const login_form = document.getElementById('login') as HTMLFormElement;

const authtastic_client = (() => {
  const urlSearchParams = new URLSearchParams(location.search);

  const return_uri = urlSearchParams.get('return_uri');
  const pub_key = urlSearchParams.get('pub_key');

  if (!return_uri || !pub_key) {
    return null;
  }

  (document.getElementById('your-app') as HTMLDivElement).classList.add('inactive');
  simulate_redirect_button.disabled = true;

  (document.getElementById('authtastic-client') as HTMLDivElement).classList.remove('inactive');

  login_form.childNodes.forEach((element) => {
    if (element instanceof HTMLInputElement) {
      element.disabled = false;
    }
  });

  return new AuthtasticClient({
    url: 'http://localhost:3333',
    redirect_opts: {
      referer_pub_key: pub_key,
      referer_return_uri: return_uri,
    },
  });
})();

simulate_redirect_button.addEventListener('click', () => {
  redirectToAuthtastic({ return_uri: location.origin, redirect_uri: location.origin });
});

handleReturnFromAuthtastic().then((token) => {
  token_el.textContent = `User Token: ${token}`;
}).catch(() => {
  token_el.textContent = 'User Token: ...';
});

login_form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const form = new FormData(login_form);

  const username = form.get('username') as string;
  const password = form.get('password') as string;

  await authtastic_client?.register(username, password);
  await authtastic_client?.login(username, password);

  await authtastic_client?.redirect();
});
