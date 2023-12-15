package starkcurve

type TestData struct {
	Settlement               Settlement               `json:"settlement"`
	TransferOrder            TransferOrder            `json:"transfer_order"`
	ConditionalTransferOrder ConditionalTransferOrder `json:"conditional_transfer_order"`
	MetaData                 MetaData                 `json:"meta_data"`
}

type Settlement struct {
	PartyAOrder    Order `json:"party_a_order"`
	PartyBOrder    Order `json:"party_b_order"`
	SettlementInfo struct {
		PartyBSold string `json:"party_b_sold"`
		PartyASold string `json:"party_a_sold"`
	} `json:"settlement_info"`
}

type Order struct {
	VaultIDSell         int64     `json:"vault_id_sell"`
	VaultIDBuy          int64     `json:"vault_id_buy"`
	AmountSell          string    `json:"amount_sell"`
	AmountBuy           string    `json:"amount_buy"`
	TokenSell           string    `json:"token_sell"`
	TokenBuy            string    `json:"token_buy"`
	Nonce               int64     `json:"nonce"`
	ExpirationTimestamp int64     `json:"expiration_timestamp"`
	Signature           Signature `json:"signature"`
	PublicKey           string    `json:"public_key"`
}

type Signature struct {
	R string `json:"r"`
	S string `json:"s"`
}

type TransferOrder struct {
	Amount              string    `json:"amount"`
	ExpirationTimestamp int64     `json:"expiration_timestamp"`
	Nonce               int64     `json:"nonce"`
	TargetPublicKey     string    `json:"target_public_key"`
	TargetVaultID       int64     `json:"target_vault_id"`
	SenderVaultID       int64     `json:"sender_vault_id"`
	Token               string    `json:"token"`
	Signature           Signature `json:"signature"`
	PublicKey           string    `json:"public_key"`
}

type ConditionalTransferOrder struct {
	Amount              string    `json:"amount"`
	ExpirationTimestamp int64     `json:"expiration_timestamp"`
	Nonce               int64     `json:"nonce"`
	TargetPublicKey     string    `json:"target_public_key"`
	TargetVaultID       int64     `json:"target_vault_id"`
	SenderVaultID       int64     `json:"sender_vault_id"`
	Token               string    `json:"token"`
	Signature           Signature `json:"signature"`
	PublicKey           string    `json:"public_key"`
	Condition           string    `json:"condition"`
}

type MetaData struct {
	PartyAOrder struct {
		MessageHash string `json:"message_hash"`
		PrivateKey  string `json:"private_key"`
	} `json:"party_a_order"`
	PartyBOrder struct {
		MessageHash string `json:"message_hash"`
		PrivateKey  string `json:"private_key"`
	} `json:"party_b_order"`
	TransferOrder struct {
		MessageHash string `json:"message_hash"`
		PrivateKey  string `json:"private_key"`
	} `json:"transfer_order"`
	ConditionalTransferOrder struct {
		MessageHash string `json:"message_hash"`
		PrivateKey  string `json:"private_key"`
	} `json:"conditional_transfer_order"`
}
