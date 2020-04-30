// type KeyStore interface {
// 	GetAddressForKeyName(keyName string) (keyAddress crypto.Address, err error)
// 	GenerateKey(ctx context.Context, in *GenRequest) (*GenResponse, error)
// 	PublicKey(ctx context.Context, in *PubRequest) (*PubResponse, error)
// 	Sign(ctx context.Context, in *SignRequest) (*SignResponse, error)
// }