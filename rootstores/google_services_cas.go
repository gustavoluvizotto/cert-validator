package rootstores

const (
	googleServicesURL  = "https://pki.goog/roots.pem"
	GoogleServicesFile = "google_services_root.pem"
)

func DownloadGoogleServicesRoot() error {
	err := Download(googleServicesURL, GoogleServicesFile)
	if err != nil {
		return err
	}
	return nil
}
