package common

type ClientType int

func (receiver ClientType) String() string {
	switch receiver {
	case ClientTypeLayer1SecretInput:
		return "2 - 1 密钥输入 客户端"
	case ClientTypeLayer2SecretInput:
		return "5 - 3 密钥输入 客户端"
	case ClientTypeSpecialLayer0CryptTextKeeper:
		return "离线保存 最终密文保存 客户端"
	case ClientTypeSpecialLayer2CryptTextKeeper:
		return "离线保存 密钥密文保存 客户端"
	case ClientTypeSpecialLayer1SecretInput:
		return "离线保存 2 - 1 密钥输入客户端"
	case ClientTypeSpecialLayer2SecretInput:
		return "离线保存 5 - 3 密钥输入客户端"
	case ClientTypeNode:
		return "MPC 节点 客户端"
	case ClientTypeKeyManager:
		return "Key Manager"
	default:
		return "unknow client type"
	}
}

const (
	// ClientTypeLayer1SecretInput 2/1 客户端
	ClientTypeLayer1SecretInput ClientType = 1
	// ClientTypeLayer2SecretInput 5/3 客户端
	ClientTypeLayer2SecretInput ClientType = 2
	// ClientTypeSpecialLayer0CryptTextKeeper 离线客户端 - 最终密文保存客户端 (保存着 trueKeys)
	ClientTypeSpecialLayer0CryptTextKeeper ClientType = 11
	// ClientTypeSpecialLayer2CryptTextKeeper 离线客户端 - 密钥密文保存客户端 (保存着 分片密钥)
	ClientTypeSpecialLayer2CryptTextKeeper ClientType = 12
	// ClientTypeSpecialLayer1SecretInput 离线客户端 - 密钥输入客户端 (2 - 1)
	ClientTypeSpecialLayer1SecretInput ClientType = 13
	// ClientTypeSpecialLayer2SecretInput 离线客户端 - 密钥输入客户端 (5 -3)
	ClientTypeSpecialLayer2SecretInput ClientType = 14
	// ClientTypeNode mpc 节点 客户端
	ClientTypeNode ClientType = 21
	// ClientTypeKeyManager key manager 服务节点
	ClientTypeKeyManager ClientType = 999
)
