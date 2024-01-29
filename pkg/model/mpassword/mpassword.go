package mpassword

type MPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

func New(username, password, url string) *MPassword {
	return &MPassword{
		Username: username,
		Password: password,
		URL:      url,
	}
}
