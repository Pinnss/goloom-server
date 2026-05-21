//go:build !linux

package mobile

import "errors"

// ConnectVKTurnSRTP non-linux stub. The mobile SDK is only built for
// android (linux) in production; desktop hosts hit this path during
// CI compile and we return a typed error so the test surface stays
// uniform.
func (c *Client) ConnectVKTurnSRTP(_ string, _ int) (string, error) {
	return "", mobileErr(ErrUnknown, errors.New("vk-turn-srtp client: not supported on this OS target (Linux/Android only)"))
}
