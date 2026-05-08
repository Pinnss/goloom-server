// Lobby DIAL — клиентская сторона in-band bootstrap'а (S2/S3).
//
// Клиент peer-join'ится в стабильный lobby VK звонок (его URL
// зашит в connstr — `LobbyMeetingURL`), находит сервер в roster'е,
// шлёт goloom_ctrl DIAL с реальным target meeting URL'ом + bearer'ом,
// ждёт DIAL_OK, leave'ит lobby и продолжает обычным transport.Connect
// в target. Сервер на DIAL делает то же самое со своей стороны.
//
// Bootstrap идёт ТОЛЬКО через videowebrtc.okcdn.ru/ws2 (lobby SFU
// signaling) — никаких прямых WSS клиента к нашему VPS.

package wgclient

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls"
)

// lobbyDial выполняет один DIAL раунд через lobby. На успех
// возвращается serverTargetUID — userID который сервер получит в
// target meeting'е (pre-authed). Клиент использует его как
// targetRemoteID для своего peer'а в target call'е, обходя
// засранный roster.
func lobbyDial(ctx context.Context, lg *log.Logger, lobbyMeeting, bearer, targetMeeting, displayName string) (int64, error) {
	if targetMeeting == "" {
		return 0, errors.New("lobby dial: target meeting URL required")
	}

	dctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	lg.Printf("lobby: peer-joining %s for DIAL bootstrap", lobbyMeeting)
	// Captcha solver для lobby auth — open default browser via AutoProxy.
	// Профайл-стора у клиента нет (он есть только серверной стороне);
	// первый раз пользователь решит captcha вручную.
	solver := vkcalls.AutoProxyCaptchaSolver(2*time.Minute, lg, nil)
	lobby, err := vkcalls.OpenLobbyPeer(dctx, lg, vkcalls.LobbyOptions{
		MeetingURL:    lobbyMeeting,
		DisplayName:   displayName,
		CaptchaSolver: solver,
	})
	if err != nil {
		return 0, fmt.Errorf("open lobby peer: %w", err)
	}
	defer lobby.Close()

	// Дождёмся появления сервера в roster'е. После connection
	// notification в peer.adoptParticipants выставится remoteID
	// если сервер уже там был (lobby был «заранее»). На свежий
	// lobby участник участвует через participant-joined.
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	var serverID int64
	for serverID == 0 {
		select {
		case <-dctx.Done():
			return 0, fmt.Errorf("lobby: timed out waiting for server peer: %w", dctx.Err())
		case <-deadline.C:
			return 0, errors.New("lobby: no server peer in roster after 20s — is server inbound running?")
		case <-tick.C:
			serverID = lobby.RemotePeerID()
		}
	}
	lg.Printf("lobby: ✓ server peer in roster id=%d, sending DIAL", serverID)

	if err := lobby.SendCtrl(serverID, vkcalls.GoloomCtrl{
		Type:       "DIAL",
		MeetingURL: targetMeeting,
		Bearer:     bearer,
	}); err != nil {
		return 0, fmt.Errorf("lobby: send DIAL: %w", err)
	}

	// Ждём DIAL_OK / DIAL_FAIL.
	for {
		select {
		case <-dctx.Done():
			return 0, fmt.Errorf("lobby: timed out waiting for DIAL response: %w", dctx.Err())
		case msg, ok := <-lobby.Incoming():
			if !ok {
				return 0, errors.New("lobby: incoming channel closed")
			}
			switch msg.Msg.Type {
			case "DIAL_OK":
				lg.Printf("lobby: ✓ DIAL_OK session=%s server_target_user_id=%d",
					msg.Msg.SessionID, msg.Msg.ServerTargetUserID)
				return msg.Msg.ServerTargetUserID, nil
			case "DIAL_FAIL":
				return 0, fmt.Errorf("lobby: server rejected DIAL: %s", msg.Msg.Reason)
			default:
				lg.Printf("lobby: ignoring unexpected ctrl type=%s", msg.Msg.Type)
			}
		}
	}
}
