package mobile

import (
	"time"

	"github.com/Pinnss/goloom-server/pkg/wgclient"
)

// vkIdentityFallbackTTL bounds reuse when a credential does not decode. VK
// issues TURN REST credentials whose username carries their own expiry, and
// that is what we normally honour — it runs for hours, so a reconnect does not
// cost another captcha. This conservative value is only for credentials in some
// other shape, where guessing long would mean handing VK dead credentials.
const vkIdentityFallbackTTL = 10 * time.Minute

// vkIdentityExpiryMargin keeps a credential from being reused in the last
// moments of its life, where it could expire between the check and the TURN
// allocate it is about to be used for.
const vkIdentityExpiryMargin = 2 * time.Minute

// usableUntil is when an identity stops being worth reusing.
func usableUntil(id wgclient.TURNIdentity, minted time.Time) time.Time {
	if _, exp, ok := wgclient.TURNUserID(id.Creds.Username); ok {
		return exp.Add(-vkIdentityExpiryMargin)
	}
	return minted.Add(vkIdentityFallbackTTL)
}

// freshIdentities returns the cached identities that are still inside the TTL
// and were minted for the same transport. A UseTCP flip changes how every
// allocation is made, so credentials from the other mode are not reused.
func (c *Client) freshIdentities(useTCP bool) []wgclient.TURNIdentity {
	c.identMu.Lock()
	defer c.identMu.Unlock()
	if len(c.vkIdentities) == 0 || c.vkIdentityTCP != useTCP {
		return nil
	}
	now := time.Now()
	out := make([]wgclient.TURNIdentity, 0, len(c.vkIdentities))
	for _, id := range c.vkIdentities {
		if now.Before(usableUntil(id, c.vkIdentityAt)) {
			out = append(out, id)
		}
	}
	// Drop what expired so a later call does not re-filter the same corpses.
	c.vkIdentities = append(c.vkIdentities[:0], out...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// storeIdentities remembers identities for a later connect. An empty set clears
// the cache rather than leaving a stale one behind.
func (c *Client) storeIdentities(ids []wgclient.TURNIdentity, useTCP bool) {
	c.identMu.Lock()
	defer c.identMu.Unlock()
	if len(ids) == 0 {
		c.vkIdentities = nil
		return
	}
	c.vkIdentities = make([]wgclient.TURNIdentity, len(ids))
	copy(c.vkIdentities, ids)
	c.vkIdentityTCP = useTCP
	c.vkIdentityAt = time.Now()
}
