// Composer-solver: пытается пройти captcha через [SolveCaptchaV2]
// (auto-replay по [ProfileStore]), на любую неудачу фоллбэкается на
// переданный base solver (обычно AdminWebview / AutoProxy).
//
// Поведение:
//  - Пул пуст → сразу base.
//  - Пул не пуст → Pick() профиль → SolveCaptchaV2:
//      успех    → MarkSuccess + return token
//      slider   → НЕ MarkFail (профиль не виноват), → fallback на base
//      bot      → MarkFail (с этим FP больше не пробуем) → fallback
//      др.фейл  → MarkFail → fallback
//  - base также используется для capture'а нового FP (loggingTransport
//    цепляется через CaptchaBroker.SetProfileStore — см. admin/captcha.go),
//    так что после ручного solve пул пополнится и следующий captcha
//    пройдёт без UI.

package vkauth

import (
	"context"
	"errors"
	"log"

	"github.com/Pinnss/goloom-server/internal/sfu"
)

// WithReplaySolver оборачивает base-solver auto-replay logic'ой.
// store — пул FP. Если store == nil — возвращает base без изменений.
//
// Внутри пикает свежий [BrowserProfile] для sec-ch-ua-* (UA при этом
// перезаписывается на сохранённый из CapturedProfile.UserAgent — он
// «доказан» на проде). Auth-ладдер использует свой собственный
// PickProfile() — fingerprint'ы могут разойтись между ладдером и
// captcha replay, что не должно быть критично: VK API endpoints для
// auth и для captchaNotRobot разные, и реальные браузеры могут менять
// UA посередине сессии (расширения, обновления). При желании — можно
// прокинуть один профиль через AuthSpec.Profile в S1c-polish.
func WithReplaySolver(store *ProfileStore, base sfu.VKCaptchaSolver, lg *log.Logger) sfu.VKCaptchaSolver {
	if store == nil {
		return base
	}
	return func(ctx context.Context, ch sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
		picked := store.Pick()
		if picked == nil {
			if lg != nil {
				lg.Printf("vkcalls/captcha-replay: pool empty, falling back to interactive solver")
			}
			return base(ctx, ch)
		}
		if lg != nil {
			lg.Printf("vkcalls/captcha-replay: trying profile %s (success=%d fail=%d ua=%s)",
				picked.ID, picked.Successes, picked.Failures, shortUA(picked.UserAgent))
		}
		token, err := SolveCaptchaV2(ctx, ch, PickProfile(), picked, lg)
		if err == nil {
			store.MarkSuccess(picked.ID)
			if lg != nil {
				lg.Printf("vkcalls/captcha-replay: ✓ profile %s succeeded", picked.ID)
			}
			return sfu.VKCaptchaSolution{SuccessToken: token}, nil
		}
		// На slider ProfileStore не виноват — сам challenge другой
		// разновидности. Не штрафуем профиль, просто fallback.
		if !errors.Is(err, ErrSliderUnsupported) {
			store.MarkFail(picked.ID)
		}
		if lg != nil {
			lg.Printf("vkcalls/captcha-replay: profile %s failed (%v), falling back to interactive", picked.ID, err)
		}
		// ctx может быть исчерпан replay-attempt'ом; для fallback
		// пройти по нему ещё раз.
		if ctx.Err() != nil {
			return sfu.VKCaptchaSolution{}, ctx.Err()
		}
		return base(ctx, ch)
	}
}
