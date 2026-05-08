// In-band ctrl-протокол: client ↔ server обмениваются короткими
// JSON-конвертами через VK SFU's transmit-data envelope. Это та же
// signaling-WS ws://videowebrtc.okcdn.ru/ws2 что несёт обычный VK
// звонок — DPI видит только ходку к VK инфре, никакого прямого
// коннекта к нашему VPS.
//
// Lobby — это стабильный VK звонок, в котором сервер постоянно
// сидит как peer (БЕЗ pion PeerConnection — только WS-listener).
// Клиент кратко peer-join'ится в lobby, шлёт серверу DIAL с meeting
// URL'ом для нужной сессии, получает DIAL_OK, выходит из lobby и идёт
// в target meeting. Сервер тоже идёт в target. Они peer-connect'ятся
// там VP8 как обычно.
//
// Сообщения:
//
//	client → server:
//	  { "goloom_ctrl": "DIAL", "meeting_url": "...", "bearer": "..." }
//
//	server → client:
//	  { "goloom_ctrl": "DIAL_OK", "session_id": "..." }
//	  { "goloom_ctrl": "DIAL_FAIL", "reason": "..." }
//	  { "goloom_ctrl": "STATUS", "phase": "...", "detail": "..." }
//
// Все доставляются через transmit-data participantId-routed envelope —
// то есть SFU доставляет точно нужному peer'у в звонке.

package vkcalls

// GoloomCtrl — payload встроенный в transmit-data.data.
type GoloomCtrl struct {
	Type       string `json:"goloom_ctrl"`
	MeetingURL string `json:"meeting_url,omitempty"`
	Bearer     string `json:"bearer,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// IncomingCtrl — control сообщение пришедшее от другого peer'а в
// lobby звонке.
type IncomingCtrl struct {
	From int64 // participantID отправителя
	Msg  GoloomCtrl
}
