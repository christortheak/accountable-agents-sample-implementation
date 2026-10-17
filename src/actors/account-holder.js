// A person with an account at a service (for example an organization's admin
// at a model-hosting platform), holding a passkey for that service. In the
// simulator the passkey lives in a software authenticator standing in for
// Touch ID / Face ID on their own device; the browser demo uses a real one.
import { getJson, postJson } from '../lib/http.js';
import { SoftwareAuthenticator } from '../lib/webauthn.js';
import { RP_METADATA_PATH } from '../lib/protocol.js';

export class AccountHolder {
  constructor({ name, account }) {
    this.name = name;
    this.account = account;
    this.authenticator = new SoftwareAuthenticator();
  }

  async origin(rp) {
    return (await getJson(`${rp.url}${RP_METADATA_PATH}`)).webauthn.origin;
  }

  async registerPasskey(rp) {
    const opts = await postJson(`${rp.url}/accounts/${this.account}/passkeys/options`, {});
    const credential = this.authenticator.create(opts.publicKey, await this.origin(rp));
    return postJson(`${rp.url}/accounts/${this.account}/passkeys`, { credential });
  }

  async pendingRequests(rp) {
    return (await getJson(`${rp.url}/accounts/${this.account}/requests`)).requests;
  }

  /** Approve a pending request with the passkey (the challenge commits to the request's details). */
  async approve(rp, requestId) {
    const opts = await postJson(`${rp.url}/approval-requests/${requestId}/options`, {});
    const credential = this.authenticator.get(opts.publicKey, await this.origin(rp));
    return postJson(`${rp.url}/approval-requests/${requestId}/approve`, { credential });
  }

  /** Human path: approve one exact request of one's own (no agent involved), returning its approval id. */
  async approveOwnRequest(rp, action, params) {
    const req = await postJson(`${rp.url}/accounts/${this.account}/human-requests`, { action, params });
    await this.approve(rp, req.request_id);
    return req.request_id;
  }
}
