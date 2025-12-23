package config

type User struct {
	ID    string
	Phone string
	Email string
	Name  string
}

type Branding struct {
	ServiceName  string
	LogoURL      string
	PrimaryColor string
	Title        string
	Subtitle     string
}

type Config struct {
	Issuer      string
	Audience    string
	Port        int
	CORSOrigins []string
	Users       []User
	Branding    Branding
}
