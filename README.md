# go-token-manager
JWT manager implemented by golang.

# Example

## Create token manager (keys read from file)

### Code

```go
func createTokenManager() (*token.TokenManager, error) {
	return token.CreateTokenManager(token.CreateTokenManagerOption{
		SigningAlgorithm: "ES256",
		PrivateKeyLoader: func() interface{} {
			keyData, e := ioutil.ReadFile("./assets/ec256-private.pem")
			if e != nil {
				panic(e.Error())
			}
			key, e := jwt.ParseECPrivateKeyFromPEM(keyData)
			if e != nil {
				panic(e.Error())
			}
			return key
		},
		PublicKeyLoader: func() interface{} {
			keyData, e := ioutil.ReadFile("./assets/ec256-public.pem")
			if e != nil {
				panic(e.Error())
			}
			key, e := jwt.ParseECPublicKeyFromPEM(keyData)
			if e != nil {
				panic(e.Error())
			}
			return key
		},
	})
}
```

### Create keys

```bash
mkdir assets; cd assets
openssl ecparam -genkey -name prime256v1 -noout -out ec256-key-pair.pem
openssl ec -in ec256-key-pair.pem -outform PEM -pubout -out ec256-public.pem
openssl ec -in ec256-key-pair.pem -outform PEM -out ec256-private.pem
```

## Create token manager (keys read from bindata)

### Code

```go
func createTokenManager() (*token.TokenManager, error) {
	return token.CreateTokenManager(token.CreateTokenManagerOption{
		SigningAlgorithm: "ES256",
		PrivateKeyLoader: func() interface{} {
			keyData, e := bindata.Asset("./ec256-private.pem")
			if e != nil {
				panic(e.Error())
			}
			key, e := jwt.ParseECPrivateKeyFromPEM(keyData)
			if e != nil {
				panic(e.Error())
			}
			return key
		},
		PublicKeyLoader: func() interface{} {
			keyData, e := bindata.Asset("./ec256-public.pem")
			if e != nil {
				panic(e.Error())
			}
			key, e := jwt.ParseECPublicKeyFromPEM(keyData)
			if e != nil {
				panic(e.Error())
			}
			return key
		},
	})
}
```

### Create keys and bindata

```bash
mkdir assets; cd assets
openssl ecparam -genkey -name prime256v1 -noout -out ec256-key-pair.pem
openssl ec -in ec256-key-pair.pem -outform PEM -pubout -out ec256-public.pem
openssl ec -in ec256-key-pair.pem -outform PEM -out ec256-private.pem
cd ../
go-bindata -o bindata/bindata.go -prefix "assets/" -pkg "bindata" assets/...
```

## Get signed token string

```go
m, err := createTokenManager()
if err != nil {
    panic(err)
}
token, err := m.CreateSignedToken(m.CreateToken(u.ID))
if err != nil {
    panic(err)
}
```

## Parse header token and get sub

```go
m, err := createTokenManager()
if err != nil {
    panic(err)
}
t, err := m.ParseTokenFromRequest(r)
if err != nil {
    panic(err)
}
if claims, ok := t.Claims.(jwt.MapClaims); !ok || !t.Valid {
	panic("invalid")
} else if id, ok := claims["sub"].(string); !ok {
	panic("invalid")
} else {
    fmt.Printf("sub is %s", id)
}
```
