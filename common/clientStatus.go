package common

type ClientStatus int

const (
	// WaitInit 等待客户端上报 节点类型, 节点index, 准备进行的操作等消息
	WaitInit ClientStatus = 0
	// InitSecret 初始化生成 mpc 私钥等消息
	InitSecret ClientStatus = 1
	// StartMPCNode 启动 mpc 节点
	StartMPCNode ClientStatus = 2
	// ResetPassword 重置 5-3/ 2-1 等客户端密码
	ResetPassword ClientStatus = 3
	// DecodeOffline 解密离线储存节点信息
	DecodeOffline ClientStatus = 10
)
