// Agent-to-relying-party presentation.
//
// The agent sends its ordinary HTTP request with:
//   AAF-Presentation: base64url JSON { v, accountability, authorization?, approval? }
//     each holder-bound credential is an SD-JWT VC with a Key Binding JWT
//     (aud = the relying party, nonce = the request's signature nonce)
//   Signature-Input / Signature / Content-Digest: RFC 9421 over the method,
//     target URI, body digest, content type and the presentation header,
//     signed with the same per-relying-party key (keyid "cnf:<thumbprint>")
// This is the Web Bot Auth pattern, with the signing key taken from the
// presented credential rather than from a key directory.
import { randomId, b64u } from './crypto.js';
import { addKeyBinding } from './sd-jwt.js';
import { signRequest } from './httpsig.js';
import { AGENT_SIGNATURE_TAG, AGENT_SIGNED_COMPONENTS } from './credentials.js';
import { HEADERS } from './protocol.js';

export function buildPresentationRequest({ url, rpId, params = {}, accountability, authorization, approval, key }) {
  const nonce = randomId('n', 12);
  const bound = (sdjwt) => addKeyBinding(sdjwt, key, { aud: rpId, nonce });
  const presentation = b64u.encodeJson({
    v: 2,
    accountability: bound(accountability),
    ...(authorization ? { authorization: bound(authorization) } : {}),
    ...(approval ? { approval } : {}),
  });
  const body = JSON.stringify(params);
  const headers = signRequest({
    method: 'POST', url, body, key, keyid: `cnf:${key.kid}`, tag: AGENT_SIGNATURE_TAG, nonce,
    components: AGENT_SIGNED_COMPONENTS,
    headers: { 'content-type': 'application/json', [HEADERS.presentation]: presentation },
  });
  return { body, headers, nonce };
}
