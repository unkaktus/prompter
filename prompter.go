package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/keybase/go-keychain"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/term"
)

type SecretData struct {
	Password string `json:"password"`
	TOTPURL  string `json:"totp_url"`
}

func generateCode(secret string, offset int) string {
	code, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second*time.Duration(offset)))
	if err != nil {
		log.Fatalf("generate OTP code: %v", err)
	}
	return code
}

func findAccount() (string, error) {
	for _, arg := range os.Args[1:] {
		sp := strings.Split(arg, "{")
		if len(sp) != 2 {
			continue
		}
		sp = strings.Split(sp[1], "}")
		if len(sp) != 2 {
			continue
		}
		return sp[0], nil

	}
	return "", fmt.Errorf("account not found")
}

func run() error {
	service := "prompter"
	account, err := findAccount()
	if err != nil {
		return err
	}
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	} else {
		for _, r := range results {
			// fmt.Printf("%#v\n", r)
			data := SecretData{}
			if err := json.Unmarshal(r.Data, &data); err != nil {
				return err
			}
			// fmt.Printf("data: %+v\n", data)
			key, err := otp.NewKeyFromURL(data.TOTPURL)
			if err != nil {
				return err
			}

			// Cleanup the command
			args := []string{}
			for _, arg := range os.Args[1:] {
				args = append(args, strings.ReplaceAll(arg, "{"+account+"}", account))
			}

			cmd := exec.Command(args[0], args[1:]...)

			// Start the command with a pty.
			ptmx, err := pty.Start(cmd)
			if err != nil {
				return fmt.Errorf("execute ssh: %w", err)
			}
			// Make sure to close the pty at the end.
			defer func() { ptmx.Close() }() // Best effort.

			// Handle pty size.
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGWINCH)
			go func() {
				for range ch {
					if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
						log.Printf("error resizing pty: %s", err)
					}
				}
			}()
			ch <- syscall.SIGWINCH                        // Initial resize.
			defer func() { signal.Stop(ch); close(ch) }() // Cleanup signals when done.

			// Set stdin in raw mode.
			oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
			if err != nil {
				panic(err)
			}
			defer func() { term.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.

			// Copy stdin to the pty and the pty to stdout.
			go func() {
				_, _ = io.Copy(ptmx, os.Stdin)
			}()

			pf := NewPromptFinder(ptmx, func(s string) (bool, string) {
				promptPresent := strings.HasSuffix(s, ":")
				if !promptPresent {
					return false, ""
				}
				s = strings.ToLower(s)
				switch {
				case strings.Contains(s, "otp") || strings.Contains(s, "mfa"):
					return true, "otp"
				case strings.Contains(s, "password"):
					return true, "password"
				}
				return true, "unknown"
			})

			go func() {
				otpOffsetNumber := 0
				otpOffsets := []int{0, 1, -1, 2, -2}
				lastPromptType := ""
				for prompt := range pf.Found {
					if prompt.Type == "unknown" {
						continue
					}
					fmt.Printf("{inserted %s}", prompt.Type)
					command := ""
					switch prompt.Type {
					case "password":
						command = fmt.Sprintf("%s\n", data.Password)
					case "otp":
						if lastPromptType == "otp" {
							otpOffsetNumber += 1
						}
						if otpOffsetNumber > len(otpOffsets)-1 {
							log.Fatalf("tried all OTPs")
						}
						code := generateCode(key.Secret(), otpOffsets[otpOffsetNumber])
						command = fmt.Sprintf("%s\n", code)
					}
					lastPromptType = prompt.Type
					_, err := fmt.Fprintf(ptmx, "%s\n", command)
					if err != nil {
						log.Fatalf("write command to the remote: %v", err)
					}
				}

			}()
			_, _ = io.Copy(os.Stdout, pf)
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
