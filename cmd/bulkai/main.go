package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/igolaizola/bulkai"
	"github.com/igolaizola/bulkai/pkg/session"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/peterbourgon/ff/v3/ffyaml"
	"golang.org/x/term"
)

// Build flags
var Version = ""
var Commit = ""
var Date = ""

func main() {
	// Create signal based context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Launch command
	cmd := newCommand()
	if err := cmd.ParseAndRun(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func newCommand() *ffcli.Command {
	fs := flag.NewFlagSet("bulkai", flag.ExitOnError)

	return &ffcli.Command{
		ShortUsage: "bulkai [flags] <subcommand>",
		FlagSet:    fs,
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
		Subcommands: []*ffcli.Command{
			newGenerateCommand(),
			newCreateSessionCommand(),
			newVersionCommand(),
		},
	}
}

func newGenerateCommand() *ffcli.Command {
	fs := flag.NewFlagSet("bulk", flag.ExitOnError)
	_ = fs.String("config", "config.yaml", "config file (optional)")

	cfg := &bulkai.Config{}
	fs.StringVar(&cfg.Bot, "bot", "", "bot name")
	var prompts fsStrings
	fs.Var(&prompts, "prompt", "prompt list")
	fs.StringVar(&cfg.Proxy, "proxy", "", "proxy address (optional)")
	fs.StringVar(&cfg.Output, "output", "output", "output directory")
	fs.StringVar(&cfg.Album, "album", "", "album id (optional)")
	fs.StringVar(&cfg.Prefix, "prefix", "", "prefix to be added")
	fs.StringVar(&cfg.Suffix, "suffix", "", "suffix to be added")
	fs.BoolVar(&cfg.Variation, "variation", false, "generate variations")
	fs.BoolVar(&cfg.Download, "download", true, "download images")
	fs.BoolVar(&cfg.Upscale, "upscale", true, "upscale images")
	fs.BoolVar(&cfg.Thumbnail, "thumbnail", true, "generate thumbnails")
	fs.BoolVar(&cfg.Html, "html", true, "generate html files")
	fs.StringVar(&cfg.Channel, "channel", "", "channel in format guid/channel (optional, if not provided DMs will be used)")
	fs.IntVar(&cfg.Concurrency, "concurrency", 3, "concurrency (optional, if 0 the maximum for the bot will be used)")
	fs.DurationVar(&cfg.Wait, "wait", 0, "wait time between prompts (optional)")
	fs.BoolVar(&cfg.Debug, "debug", false, "debug mode")
	fs.StringVar(&cfg.ReplicateToken, "replicate-token", "", "replicate token (optional)")
	fs.BoolVar(&cfg.MidjourneyCDN, "midjourney-cdn", false, "use midjourney cdn instead of discord cdn")

	// Session
	fs.StringVar(&cfg.SessionFile, "session", "session.yaml", "session config file (optional)")

	fsSession := flag.NewFlagSet("", flag.ExitOnError)
	for _, fs := range []*flag.FlagSet{fs, fsSession} {
		fs.StringVar(&cfg.Session.UserAgent, "user-agent", "", "user agent")
		fs.StringVar(&cfg.Session.JA3, "ja3", "", "ja3 fingerprint")
		fs.StringVar(&cfg.Session.Language, "language", "", "language")
		fs.StringVar(&cfg.Session.Token, "token", "", "authentication token")
		fs.StringVar(&cfg.Session.SuperProperties, "super-properties", "", "super properties")
		fs.StringVar(&cfg.Session.Locale, "locale", "", "locale")
		fs.StringVar(&cfg.Session.Cookie, "cookie", "", "cookie")
	}

	return &ffcli.Command{
		Name:       "generate",
		ShortUsage: "bulkai generate [flags] <key> <value data...>",
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ffyaml.Parser),
			ff.WithEnvVarPrefix("BULKAI"),
		},
		ShortHelp: "generate images in bulk",
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			ch := make(chan bool)
			go tryLoginFromCache(ch)
			result := <-ch
			if !result {
				fmt.Println("login failed. Please try again")
				return nil
			}
			loadSession(fsSession, cfg.SessionFile)
			cfg.Prompts = prompts
			last := 0
			return bulkai.Generate(ctx, cfg, bulkai.WithOnUpdate(func(s bulkai.Status) {
				curr := int(s.Percentage)
				if curr == last {
					return
				}
				last = curr
				fmt.Printf("{\"progress\": \"%d\", \"estimated\": \"%s\"}\n", curr, s.Estimated)
			}))
		},
	}
}

func newCreateSessionCommand() *ffcli.Command {
	fs := flag.NewFlagSet("create-session", flag.ExitOnError)
	_ = fs.String("config", "", "config file (optional)")

	output := fs.String("output", "session.yaml", "output file (optional)")
	proxy := fs.String("proxy", "", "proxy server (optional)")
	profile := fs.Bool("profile", false, "use profile (optional)")
	return &ffcli.Command{
		Name:       "create-session",
		ShortUsage: "bulkai create-session [flags] <key> <value data...>",
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ff.PlainParser),
			ff.WithEnvVarPrefix("BULKAI"),
		},
		ShortHelp: "create session using chrome",
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			return session.Run(ctx, *profile, *output, *proxy)
		},
	}
}

func newVersionCommand() *ffcli.Command {
	return &ffcli.Command{
		Name:       "version",
		ShortUsage: "bulkai version",
		ShortHelp:  "print version",
		Exec: func(ctx context.Context, args []string) error {
			v := Version
			if v == "" {
				if buildInfo, ok := debug.ReadBuildInfo(); ok {
					v = buildInfo.Main.Version
				}
			}
			if v == "" {
				v = "dev"
			}
			versionFields := []string{v}
			if Commit != "" {
				versionFields = append(versionFields, Commit)
			}
			if Date != "" {
				versionFields = append(versionFields, Date)
			}
			fmt.Println(strings.Join(versionFields, " "))
			return nil
		},
	}
}

func loadSession(fs *flag.FlagSet, file string) error {
	if file == "" {
		return fmt.Errorf("session file not specified")
	}
	if _, err := os.Stat(file); err != nil {
		return nil
	}
	log.Printf("loading session from %s", file)
	return ff.Parse(fs, []string{}, []ff.Option{
		ff.WithConfigFile(file),
		ff.WithConfigFileParser(ffyaml.Parser),
	}...)
}

type fsStrings []string

func (f *fsStrings) String() string {
	return strings.Join(*f, ",")
}

func (f *fsStrings) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// LOGIN ===============================================

type UserData struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Credit   int    `json:"credit"`
}

func tryLoginFromCache(ch chan<- bool) {
	// Check if the file exists
	var userData UserData
	_, err := os.Stat(getDatFilePath())
	if os.IsNotExist(err) {
		fmt.Println("login data does not exist. please login first")

		userData = loginOrRegister()
	} else {
		userData, err = loadUserData()
		if err != nil {
			fmt.Println("Error reading file:", err)
			userData = loginOrRegister()
		}
	}

	jsonData, err := json.Marshal(userData)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		return
	}

	resp, err := http.Post("https://us-central1-money-income-server.cloudfunctions.net/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Login successful")
		saveUserData(userData)
		ch <- true
	} else if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("Invalid username or password")
	} else {
		fmt.Printf("Unexpected response status: %s\n", resp.Status)
	}
}

func loginOrRegister() UserData {
	reader := bufio.NewReader(os.Stdin)
	loop := 0
	input := ""
	for {
		if loop != 0 {
			input, _ = reader.ReadString('\n')
			input = strings.TrimSpace(input)
		}

		if input == "y" {
			return loginByUser()
		} else if input == "n" {
			return register()
		} else {
			fmt.Print("Login with existing account [y/n]: ")
		}
		loop++
	}
}

func loginByUser() UserData {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter password: ")
	password := getPasswordInput()
	fmt.Println()

	// Create UserData object
	userData := UserData{
		Username: username,
		Password: password,
	}

	return userData
}

func register() UserData {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter username and password to register")
	fmt.Print("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter password: ")
	password := getPasswordInput()
	// Prompt user to repeat password
	fmt.Print("Confirm password: ")
	repeatedPassword := getPasswordInput()

	// Check if passwords match
	if password != repeatedPassword {
		fmt.Println("Passwords do not match. Please try again.")
		return register()
	}

	// Create UserData object
	userData := UserData{
		Username: username,
		Password: password,
	}

	jsonData, err := json.Marshal(userData)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
	}

	resp, err := http.Post("https://us-central1-money-income-server.cloudfunctions.net/createUser", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&userData)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
	}

	if resp.StatusCode == http.StatusCreated {
		fmt.Println("Register successful")
		return userData
	} else if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("Invalid username or password")
	} else {
		fmt.Printf("Unexpected response status: %s\n", resp.Status)
	}

	return register()
}

var encryptionKey = []byte("encryption-key-0")

func saveUserData(userData UserData) error {
	// Convert user data to JSON
	jsonData, err := json.Marshal(userData)
	if err != nil {
		return err
	}

	// Encrypt the JSON data
	encryptedData, err := encrypt(jsonData, encryptionKey)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Write JSON data to .dat file
	err = os.WriteFile(getDatFilePath(), encryptedData, 0644)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func loadUserData() (UserData, error) {
	// Read encrypted data from .dat file
	encryptedData, err := os.ReadFile(getDatFilePath())
	if err != nil {
		return UserData{}, err
	}

	// Decrypt the data
	decryptedData, err := decrypt(encryptedData, encryptionKey)
	if err != nil {
		return UserData{}, err
	}

	// Decode JSON data into UserData struct
	var userData UserData
	err = json.Unmarshal(decryptedData, &userData)
	if err != nil {
		return UserData{}, err
	}
	return userData, nil
}

func getDatFilePath() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "ImageModify", "data-go.dat")
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

func getPasswordInput() string {
	password, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return strings.TrimSpace(string(password))
}
