package main

import (
	"context"
	iorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"github.com/gotd/td/session"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"math/big"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/updates"
	updhook "github.com/gotd/td/telegram/updates/hook"
	"github.com/gotd/td/tg"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx); err != nil {
		panic(err)
	}
}

func run(ctx context.Context) error {
	log, _ := zap.NewDevelopment(zap.IncreaseLevel(zapcore.InfoLevel), zap.AddStacktrace(zapcore.ErrorLevel))
	defer func() { _ = log.Sync() }()

	d := tg.NewUpdateDispatcher()
	gaps := updates.New(updates.Config{
		Handler: d,
		Logger:  log.Named("gaps"),
	})

	op := telegram.Options{
		Logger:        log,
		UpdateHandler: gaps,
		Middlewares: []telegram.Middleware{
			updhook.UpdateHook(gaps.Handle),
		},
		SessionStorage: new(session.StorageMemory),
		RetryInterval:  5 * time.Second,
		MaxRetries:     3, // infinite retries
		DialTimeout:    10 * time.Second,
		Device:         GetDevice(),
	}
	client := telegram.NewClient(6, "eb06d4abfb49dc3eeb1aeb98ae0f581e", op)

	// Setup message update handlers.
	d.OnNewChannelMessage(func(ctx context.Context, e tg.Entities, update *tg.UpdateNewChannelMessage) error {
		log.Info("Channel message", zap.Any("message", update.Message))
		return nil
	})
	d.OnNewMessage(func(ctx context.Context, e tg.Entities, update *tg.UpdateNewMessage) error {
		log.Info("Message", zap.Any("message", update.Message))
		return nil
	})

	return client.Run(ctx, func(ctx context.Context) error {

		loginBefore(ctx, client)
		codeSettings := tg.CodeSettings{
			AllowFlashcall:  true,  // 不允许闪电电话，因为这通常需要App权限
			CurrentNumber:   false, // 假设当前使用的是注册的手机号码
			AllowAppHash:    true,  // 允许通过Telegram App接收验证码
			AllowMissedCall: true,  // 允许通过未接来电接收验证码
			AllowFirebase:   true,
			UnknownNumber:   true,
			AppSandbox:      false,
			LogoutTokens:    make([][]byte, 0),
		}
		sendCode, err := client.Auth().SendCode(ctx, "+8615975026890", auth.SendCodeOptions{
			CodeSettings: codeSettings,
		})
		if err != nil {
			return err
		}
		fmt.Sprintln(sendCode)
		// TODO 登录

		_, _ = client.API().AccountGetAutoDownloadSettings(ctx)

		_, _ = client.API().MessagesGetTopReactions(ctx, &tg.MessagesGetTopReactionsRequest{
			Limit: 100,
			Hash:  0,
		})

		_, _ = client.API().LangpackGetLanguage(ctx, &tg.LangpackGetLanguageRequest{
			LangPack: "android",
			LangCode: "en",
		})
		_, _ = client.API().MessagesGetEmojiKeywordsDifference(ctx, &tg.MessagesGetEmojiKeywordsDifferenceRequest{
			LangCode:    "en",
			FromVersion: 0,
		})

		_, _ = client.API().MessagesGetDialogFilters(ctx)
		_, _ = client.API().LangpackGetLangPack(ctx, &tg.LangpackGetLangPackRequest{
			LangPack: "android",
			LangCode: "en",
		})
		_, _ = client.API().LangpackGetDifference(ctx, &tg.LangpackGetDifferenceRequest{
			LangPack:    "android",
			LangCode:    "en",
			FromVersion: 0,
		})

		//Fetch user info.
		user, err := client.Self(ctx)
		if err != nil {
			return errors.Wrap(err, "call self")
		}

		return gaps.Run(ctx, client.API(), user.ID, updates.AuthOptions{
			OnStart: func(ctx context.Context) {
				log.Info("Gaps started")
			},
		})
	})
}

func GetDevice() telegram.DeviceConfig {
	dms := []string{"OnePlusPHP110"}
	var device = telegram.DeviceConfig{

		DeviceModel:    dms[rand.Intn(len(dms))],
		SystemVersion:  "SDK 33",
		AppVersion:     "11.7.0 (56639)",
		SystemLangCode: "en-us",
		LangPack:       "android",
		LangCode:       "en",
	}
	deviceToken := fmt.Sprintf("__FIREBASE_GENERATING_SINCE_%d__", time.Now().Unix())

	// 应用程序包名
	packageID := "org.telegram.messenger"

	// 示例数据，通常是证书指纹56
	data := generateSignature()

	// 安装来源，如果没有可以为空字符串
	installer := ""

	// 获取时区偏移量（以秒为单位）
	_, offset := time.Now().Zone()
	tzOffset := offset

	jsonObject := &tg.JSONObject{
		Value: make([]tg.JSONObjectValue, 0),
	}

	// Add device_token if currentRegId is not empty
	jsonObject.Value = append(jsonObject.Value, tg.JSONObjectValue{
		Key: "device_token",
		Value: &tg.JSONString{
			Value: deviceToken,
		},
	})

	// Add data if certFingerprint is not empty
	jsonObject.Value = append(jsonObject.Value, tg.JSONObjectValue{
		Key: "data",
		Value: &tg.JSONString{
			Value: data,
		},
	})

	// Add installer
	jsonObject.Value = append(jsonObject.Value, tg.JSONObjectValue{
		Key: "installer",
		Value: &tg.JSONString{
			Value: installer,
		},
	})

	// Add package_id
	jsonObject.Value = append(jsonObject.Value, tg.JSONObjectValue{
		Key: "package_id",
		Value: &tg.JSONString{
			Value: packageID,
		},
	})

	// Add tz_offset
	jsonObject.Value = append(jsonObject.Value, tg.JSONObjectValue{
		Key: "tz_offset",
		Value: &tg.JSONNumber{
			Value: float64(tzOffset),
		},
	})

	// Add perf_cat if currentPerformanceClass is not -1
	jsonObject.Value = append(jsonObject.Value, tg.JSONObjectValue{
		Key: "perf_cat",
		Value: &tg.JSONNumber{
			Value: float64(2),
		},
	})

	device.Params = jsonObject

	return device
}

func generateSignature() string {
	// 1. 生成 RSA 密钥对
	privateKey, _ := rsa.GenerateKey(iorand.Reader, 2048)

	// 2. 创建 X.509 证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"telegram"},
			CommonName:   "telegram",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(20, 0, 0), // 20 年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 3. 创建自签名证书 A08D7DC323DDF71EF3201944397E0D3CCE7D40847263E11F328B68BBE19229AB 0FC897ED0D705B7560A7E038A62C29208D24B9495A9BEC212968EF7DFBBFB0E6
	certBytes, _ := x509.CreateCertificate(iorand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	// 4. 计算 SHA-256 哈希
	hash := sha256.Sum256(certBytes)
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// 登录前置操作
func loginBefore(ctx context.Context, client *telegram.Client) {
	_, _ = client.API().LangpackGetLanguages(ctx, "android")
	_, _ = client.API().HelpGetNearestDC(ctx)
	_, _ = client.API().HelpGetCountriesList(ctx, &tg.HelpGetCountriesListRequest{LangCode: "en"})
}

// 登录后置操作
func loginBAfter(ctx context.Context, client *telegram.Client) {
	// 1
	getDifferenceRequest := &tg.UpdatesGetDifferenceRequest{
		Pts:           0,
		PtsTotalLimit: 5000,
		Date:          int(time.Now().Unix()),
	}
	getDifferenceRequest.SetFlags()
	_, _ = client.API().UpdatesGetDifference(ctx, getDifferenceRequest)

	// 2
	getRecentReactionsRequest := &tg.MessagesGetRecentReactionsRequest{
		Limit: 50,
		Hash:  0,
	}
	_, _ = client.API().MessagesGetRecentReactions(ctx, getRecentReactionsRequest)

	// 3
	getTopReactionsRequest := &tg.MessagesGetTopReactionsRequest{
		Limit: 100,
		Hash:  0,
	}

	_, _ = client.API().MessagesGetTopReactions(ctx, getTopReactionsRequest)

	// 4
	_, _ = client.API().AccountGetDefaultProfilePhotoEmojis(ctx, 0)

	// 5
	_, _ = client.API().AccountGetGlobalPrivacySettings(ctx)

	// 6

}
