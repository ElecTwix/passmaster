build:
	GOOS=windows go build cmd/passmaster/passmater.go

run: 
	GOOS=windows go run cmd/passmaster/passmater.go
